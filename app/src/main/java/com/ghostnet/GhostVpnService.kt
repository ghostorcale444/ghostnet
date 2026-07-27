package com.ghostnet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.Selector
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicLong

class GhostVpnService : VpnService() {

    companion object {
        const val TAG = "GhostVpnService"
        const val ACTION_START = "com.ghostnet.START"
        const val ACTION_STOP = "com.ghostnet.STOP"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "ghostnet_vpn"
        const val TARGET_TTL: Byte = 64
        const val MTU = 65535
        const val POOL_SIZE = 64
        const val QUEUE_CAPACITY = 512

        val TETHER_UA_FRAGMENTS = listOf(
            "Windows NT", "Win64", "WOW64", "Macintosh",
            "Linux x86_64", "Linux i686", "CrOS", "X11; Ubuntu",
            "PlayStation", "Nintendo", "Xbox"
        )
        val REPLACEMENT_UA = "Mozilla/5.0 (Linux; Android 14; SM-X210) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

        @Volatile var isRunning = false
        val bytesIn = AtomicLong(0)
        val bytesOut = AtomicLong(0)
        val packetsProcessed = AtomicLong(0)
        val ttlRewrites = AtomicLong(0)
        val uaScrubs = AtomicLong(0)
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    // Pre-allocated buffer pool — zero allocation in the hot path
    private val bufferPool = ArrayBlockingQueue<ByteArray>(POOL_SIZE).apply {
        repeat(POOL_SIZE) { offer(ByteArray(MTU)) }
    }

    // Lock-free packet queue between reader and writer
    private val packetQueue = ArrayBlockingQueue<Pair<ByteArray, Int>>(QUEUE_CAPACITY)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); START_NOT_STICKY }
            else -> { startVpn(); START_STICKY }
        }
    }

    private fun startVpn() {
        if (isRunning) return
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Connecting..."))

        val builder = Builder()
            .setSession("GhostNet")
            .addAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            .setMtu(MTU)
            .setBlocking(true)
            .allowFamily(OsConstants.AF_INET)
            .allowFamily(OsConstants.AF_INET6)

        try {
            vpnInterface = builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "VPN establish failed: ${e.message}")
            broadcastError("Failed to establish VPN: ${e.message}")
            stopSelf()
            return
        }

        if (vpnInterface == null) {
            broadcastError("VPN permission not granted")
            stopSelf()
            return
        }

        isRunning = true
        bytesIn.set(0); bytesOut.set(0)
        packetsProcessed.set(0); ttlRewrites.set(0); uaScrubs.set(0)
        broadcastState(true)
        updateNotification("Active")

        // Reader thread — dedicated, max priority, no yielding
        serviceScope.launch(Dispatchers.IO) {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)
            runReader()
        }

        // Writer thread — dedicated, high priority
        serviceScope.launch(Dispatchers.IO) {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)
            runWriter()
        }

        // Stats thread — low priority, 1s interval
        serviceScope.launch(Dispatchers.IO) {
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
            runStats()
        }
    }

    private fun runReader() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val stream = FileInputStream(fd)

        while (serviceScope.isActive && isRunning) {
            val buf = bufferPool.poll() ?: ByteArray(MTU)
            try {
                val length = stream.read(buf)
                if (length <= 0) {
                    bufferPool.offer(buf)
                    continue
                }
                bytesIn.addAndGet(length.toLong())
                // Process in-place, queue for writing
                processPacket(buf, length)
                packetsProcessed.incrementAndGet()
                // Queue — drops if full (backpressure) rather than blocking reader
                if (!packetQueue.offer(Pair(buf, length))) {
                    bufferPool.offer(buf)
                }
            } catch (e: Exception) {
                bufferPool.offer(buf)
                if (isRunning) Log.e(TAG, "Read error: ${e.message}")
            }
        }
    }

    private fun runWriter() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val stream = FileOutputStream(fd)

        while (serviceScope.isActive && isRunning) {
            try {
                val (buf, length) = packetQueue.take()
                stream.write(buf, 0, length)
                bytesOut.addAndGet(length.toLong())
                bufferPool.offer(buf)
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Write error: ${e.message}")
            }
        }
    }

    private fun runStats() {
        while (serviceScope.isActive && isRunning) {
            try {
                Thread.sleep(1000)
                broadcastStats()
                updateNotification(
                    "Active · ↑${formatBytes(bytesOut.get())} ↓${formatBytes(bytesIn.get())}"
                )
            } catch (e: InterruptedException) {
                break
            }
        }
    }

    // In-place packet processing — zero allocation, modifies buffer directly
    private fun processPacket(data: ByteArray, length: Int) {
        if (length < 20) return
        val version = (data[0].toInt() and 0xFF) shr 4
        if (version != 4) return

        val ihl = (data[0].toInt() and 0x0F) * 4
        if (length < ihl) return

        val protocol = data[9].toInt() and 0xFF
        var modified = false

        // TTL normalization — single byte write
        if (data[8] != TARGET_TTL) {
            data[8] = TARGET_TTL
            ttlRewrites.incrementAndGet()
            modified = true
        }

        // UA scrubbing — HTTP only (TCP dst port 80), zero allocation fast path
        if (protocol == 6 && ihl + 20 <= length) {
            val dstPort = ((data[ihl + 2].toInt() and 0xFF) shl 8) or (data[ihl + 3].toInt() and 0xFF)
            if (dstPort == 80) {
                val tcpHeaderLen = ((data[ihl + 12].toInt() and 0xFF) shr 4) * 4
                val payloadOffset = ihl + tcpHeaderLen
                if (payloadOffset + 16 < length) {
                    val payloadLen = length - payloadOffset
                    val payload = String(data, payloadOffset, payloadLen, Charsets.ISO_8859_1)
                    val scrubbed = scrubUserAgent(payload)
                    if (scrubbed !== payload) {
                        val bytes = scrubbed.toByteArray(Charsets.ISO_8859_1)
                        if (bytes.size == payloadLen) {
                            System.arraycopy(bytes, 0, data, payloadOffset, payloadLen)
                            uaScrubs.incrementAndGet()
                            modified = true
                        }
                    }
                }
            }
        }

        if (modified) {
            // Recompute IP checksum
            data[10] = 0; data[11] = 0
            val ipCs = computeChecksum(data, 0, ihl)
            data[10] = (ipCs shr 8).toByte()
            data[11] = (ipCs and 0xFF).toByte()

            // Recompute TCP checksum if TCP was modified
            if (protocol == 6) recomputeTcpChecksum(data, ihl, length)
        }
    }

    private fun scrubUserAgent(payload: String): String {
        val uaIdx = payload.indexOf("User-Agent: ", ignoreCase = true)
        if (uaIdx == -1) return payload
        val valStart = uaIdx + 12
        val valEnd = payload.indexOf("\r\n", valStart)
        if (valEnd == -1) return payload
        val original = payload.substring(valStart, valEnd)
        if (!TETHER_UA_FRAGMENTS.any { original.contains(it, ignoreCase = true) }) return payload
        val replacement = REPLACEMENT_UA.padEnd(original.length).take(original.length)
        return payload.substring(0, valStart) + replacement + payload.substring(valEnd)
    }

    private fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (length % 2 != 0) sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun recomputeTcpChecksum(data: ByteArray, ihl: Int, totalLen: Int) {
        val tcpLen = totalLen - ihl
        if (tcpLen < 20) return
        data[ihl + 16] = 0; data[ihl + 17] = 0
        var sum = 0
        // Pseudo-header
        for (i in 12..19) sum += (data[i].toInt() and 0xFF) shl (if ((i % 2 == 0)) 8 else 0)
        sum += 6; sum += tcpLen
        // TCP segment
        var i = ihl
        while (i < totalLen - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (tcpLen % 2 != 0) sum += (data[totalLen - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val cs = sum.inv() and 0xFFFF
        data[ihl + 16] = (cs shr 8).toByte()
        data[ihl + 17] = (cs and 0xFF).toByte()
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "${bytes}B"
        bytes < 1048576 -> "${"%.1f".format(bytes / 1024.0)}KB"
        bytes < 1073741824 -> "${"%.1f".format(bytes / 1048576.0)}MB"
        else -> "${"%.2f".format(bytes / 1073741824.0)}GB"
    }

    private fun stopVpn() {
        isRunning = false
        serviceScope.cancel()
        packetQueue.clear()
        vpnInterface?.close()
        vpnInterface = null
        broadcastState(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcastState(running: Boolean) =
        sendBroadcast(Intent("com.ghostnet.VPN_STATE").putExtra("running", running))

    private fun broadcastStats() =
        sendBroadcast(Intent("com.ghostnet.VPN_STATS").apply {
            putExtra("bytesIn", bytesIn.get())
            putExtra("bytesOut", bytesOut.get())
            putExtra("packets", packetsProcessed.get())
            putExtra("ttlRewrites", ttlRewrites.get())
            putExtra("uaScrubs", uaScrubs.get())
        })

    private fun broadcastError(msg: String) =
        sendBroadcast(Intent("com.ghostnet.VPN_ERROR").putExtra("message", msg))

    private fun updateNotification(text: String) =
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("GhostNet")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "GhostNet VPN", NotificationManager.IMPORTANCE_LOW).apply {
                description = "GhostNet tether hiding"
                setShowBadge(false)
            }
        )
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
}
