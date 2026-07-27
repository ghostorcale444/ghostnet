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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.atomic.AtomicLong

class GhostVpnService : VpnService() {

    companion object {
        const val TAG = "GhostVpnService"
        const val ACTION_START = "com.ghostnet.START"
        const val ACTION_STOP = "com.ghostnet.STOP"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "ghostnet_vpn"
        const val TARGET_TTL: Byte = 64

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
            .setMtu(1500)
            .setBlocking(false)
            .allowFamily(OsConstants.AF_INET)

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
        updateNotification("Active — hiding tether traffic")

        serviceScope.launch { runPacketLoop() }
        serviceScope.launch { runStatsLoop() }
    }

    private fun runPacketLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)

        // DNS upstream via protected socket
        val dnsChannel = DatagramChannel.open().apply {
            configureBlocking(false)
            protect(socket())
            connect(InetSocketAddress(InetAddress.getByName("1.1.1.1"), 53))
        }

        while (serviceScope.isActive && isRunning) {
            try {
                val length = input.read(buffer)
                if (length <= 0) {
                    Thread.sleep(1)
                    continue
                }

                bytesIn.addAndGet(length.toLong())
                packetsProcessed.incrementAndGet()

                val packet = buffer.copyOf(length)
                val processed = processPacket(packet, length)

                if (processed != null) {
                    output.write(processed, 0, length)
                    bytesOut.addAndGet(length.toLong())
                }
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Packet error: ${e.message}")
            }
        }

        dnsChannel.close()
    }

    private fun runStatsLoop() {
        while (serviceScope.isActive && isRunning) {
            try {
                Thread.sleep(1000)
                broadcastStats()
                updateNotification(
                    "Active · ↑${formatBytes(bytesOut.get())} ↓${formatBytes(bytesIn.get())} · ${packetsProcessed.get()} pkts"
                )
            } catch (e: InterruptedException) {
                break
            }
        }
    }

    private fun processPacket(data: ByteArray, length: Int): ByteArray? {
        if (length < 20) return null
        val version = (data[0].toInt() and 0xFF) shr 4
        if (version != 4) return data

        val ihl = (data[0].toInt() and 0x0F) * 4
        if (length < ihl) return null

        val protocol = data[9].toInt() and 0xFF
        var modified = false

        // TTL normalization
        if (data[8] != TARGET_TTL) {
            data[8] = TARGET_TTL
            ttlRewrites.incrementAndGet()
            modified = true
        }

        // HTTP UA scrubbing on TCP port 80
        if (protocol == 6 && ihl + 4 <= length) {
            val dstPort = ((data[ihl + 2].toInt() and 0xFF) shl 8) or (data[ihl + 3].toInt() and 0xFF)
            if (dstPort == 80) {
                val tcpHeaderLen = ((data[ihl + 12].toInt() and 0xFF) shr 4) * 4
                val payloadOffset = ihl + tcpHeaderLen
                if (payloadOffset < length) {
                    val payloadLen = length - payloadOffset
                    if (payloadLen > 16) {
                        val payload = String(data, payloadOffset, payloadLen, Charsets.ISO_8859_1)
                        val scrubbed = scrubUserAgent(payload)
                        if (scrubbed != payload) {
                            val scrubbedBytes = scrubbed.toByteArray(Charsets.ISO_8859_1)
                            if (scrubbedBytes.size == payloadLen) {
                                System.arraycopy(scrubbedBytes, 0, data, payloadOffset, payloadLen)
                                uaScrubs.incrementAndGet()
                                modified = true
                            }
                        }
                    }
                }
            }
        }

        if (modified) {
            data[10] = 0; data[11] = 0
            val checksum = computeIpChecksum(data, ihl)
            data[10] = (checksum shr 8).toByte()
            data[11] = (checksum and 0xFF).toByte()
            if (protocol == 6) recomputeTcpChecksum(data, ihl, length)
        }

        return data
    }

    private fun scrubUserAgent(payload: String): String {
        val uaHeader = "User-Agent: "
        val uaStart = payload.indexOf(uaHeader, ignoreCase = true)
        if (uaStart == -1) return payload
        val uaValueStart = uaStart + uaHeader.length
        val uaEnd = payload.indexOf("\r\n", uaValueStart)
        if (uaEnd == -1) return payload
        val originalUa = payload.substring(uaValueStart, uaEnd)
        if (!TETHER_UA_FRAGMENTS.any { originalUa.contains(it, ignoreCase = true) }) return payload
        val replacement = REPLACEMENT_UA.padEnd(originalUa.length).take(originalUa.length)
        return payload.substring(0, uaValueStart) + replacement + payload.substring(uaEnd)
    }

    private fun computeIpChecksum(data: ByteArray, headerLen: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLen - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun recomputeTcpChecksum(data: ByteArray, ihl: Int, totalLen: Int) {
        val tcpLen = totalLen - ihl
        if (tcpLen < 20) return
        data[ihl + 16] = 0; data[ihl + 17] = 0
        var sum = 0
        for (i in 12..15) sum += (data[i].toInt() and 0xFF) shl (if ((i - 12) % 2 == 0) 8 else 0)
        for (i in 16..19) sum += (data[i].toInt() and 0xFF) shl (if ((i - 16) % 2 == 0) 8 else 0)
        sum += 6; sum += tcpLen
        var i = ihl
        while (i < totalLen - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (tcpLen % 2 != 0) sum += (data[totalLen - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val checksum = sum.inv() and 0xFFFF
        data[ihl + 16] = (checksum shr 8).toByte()
        data[ihl + 17] = (checksum and 0xFF).toByte()
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "${bytes}B"
            bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)}KB"
            bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))}MB"
            else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))}GB"
        }
    }

    private fun stopVpn() {
        isRunning = false
        serviceScope.cancel()
        vpnInterface?.close()
        vpnInterface = null
        broadcastState(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcastState(running: Boolean) {
        sendBroadcast(Intent("com.ghostnet.VPN_STATE").apply {
            putExtra("running", running)
        })
    }

    private fun broadcastStats() {
        sendBroadcast(Intent("com.ghostnet.VPN_STATS").apply {
            putExtra("bytesIn", bytesIn.get())
            putExtra("bytesOut", bytesOut.get())
            putExtra("packets", packetsProcessed.get())
            putExtra("ttlRewrites", ttlRewrites.get())
            putExtra("uaScrubs", uaScrubs.get())
        })
    }

    private fun broadcastError(msg: String) {
        sendBroadcast(Intent("com.ghostnet.VPN_ERROR").apply {
            putExtra("message", msg)
        })
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

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
        val channel = NotificationChannel(CHANNEL_ID, "GhostNet VPN", NotificationManager.IMPORTANCE_LOW).apply {
            description = "GhostNet tether hiding"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
}
