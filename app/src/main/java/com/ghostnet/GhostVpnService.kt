package com.ghostnet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
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
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.Selector

class GhostVpnService : VpnService() {

    companion object {
        const val TAG = "GhostVpnService"
        const val ACTION_START = "com.ghostnet.START"
        const val ACTION_STOP = "com.ghostnet.STOP"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "ghostnet_vpn"

        // TTL value carriers use to detect tethering — tethered device TTL
        // is typically 64 or 128 decremented by 1 when forwarded, making it 63 or 127.
        // We normalize all outgoing TTLs to 64 to match phone-originated traffic.
        const val TARGET_TTL: Byte = 64

        // Carrier user-agent fingerprint strings stripped from HTTP headers
        val TETHER_UA_FRAGMENTS = listOf(
            "Windows NT",
            "Win64",
            "WOW64",
            "Macintosh",
            "Linux x86_64",
            "Linux i686",
            "CrOS",
            "X11; Ubuntu",
            "PlayStation",
            "Nintendo",
            "Xbox"
        )

        val REPLACEMENT_UA = "Mozilla/5.0 (Linux; Android 14; SM-X210) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

        @Volatile
        var isRunning = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                START_NOT_STICKY
            }
            else -> {
                startVpn()
                START_STICKY
            }
        }
    }

    private fun startVpn() {
        if (isRunning) return

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("GhostNet")
            .addAddress("10.0.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            .setMtu(1500)
            .setBlocking(true)

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }

        isRunning = true
        broadcastState(true)

        serviceScope.launch {
            runPacketLoop()
        }
    }

    private fun runPacketLoop() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(vpnFd)
        val outputStream = FileOutputStream(vpnFd)

        val packetBuffer = ByteBuffer.allocate(32767)
        val forwardBuffer = ByteBuffer.allocate(32767)

        val selector = Selector.open()
        val udpChannel = DatagramChannel.open().apply {
            configureBlocking(false)
            connect(InetAddress.getByName("8.8.8.8"), 53)
            protect(socket())
        }

        while (serviceScope.isActive && isRunning) {
            try {
                packetBuffer.clear()
                val length = inputStream.read(packetBuffer.array())
                if (length <= 0) continue

                packetBuffer.limit(length)

                // Process the IP packet
                val processed = processPacket(packetBuffer, length)

                if (processed != null) {
                    outputStream.write(processed.array(), 0, processed.limit())
                }

            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Packet loop error: ${e.message}")
                }
            }
        }

        udpChannel.close()
        selector.close()
    }

    /**
     * Core packet processing:
     * 1. Normalize TTL to 64 on all IPv4 packets
     * 2. Scrub tether-identifying User-Agent strings from HTTP traffic
     * 3. Recompute IP checksum after any modifications
     */
    private fun processPacket(buffer: ByteBuffer, length: Int): ByteBuffer? {
        if (length < 20) return null

        val data = buffer.array()

        // Verify IPv4
        val version = (data[0].toInt() and 0xFF) shr 4
        if (version != 4) return buffer

        val ihl = (data[0].toInt() and 0x0F) * 4
        if (length < ihl) return null

        val protocol = data[9].toInt() and 0xFF
        var modified = false

        // TTL normalization — offset 8 in IPv4 header
        val currentTtl = data[8]
        if (currentTtl != TARGET_TTL) {
            data[8] = TARGET_TTL
            modified = true
        }

        // HTTP user-agent scrubbing — TCP port 80 only
        if (protocol == 6 && ihl + 4 <= length) {
            val tcpDestPort = ((data[ihl + 2].toInt() and 0xFF) shl 8) or (data[ihl + 3].toInt() and 0xFF)
            val tcpSrcPort = ((data[ihl].toInt() and 0xFF) shl 8) or (data[ihl + 1].toInt() and 0xFF)

            if (tcpDestPort == 80 || tcpSrcPort == 80) {
                val tcpHeaderLen = ((data[ihl + 12].toInt() and 0xFF) shr 4) * 4
                val payloadOffset = ihl + tcpHeaderLen

                if (payloadOffset < length) {
                    val payloadLen = length - payloadOffset
                    if (payloadLen > 7) {
                        val payload = String(data, payloadOffset, payloadLen, Charsets.ISO_8859_1)
                        val scrubbed = scrubUserAgent(payload)
                        if (scrubbed != payload) {
                            val scrubbedBytes = scrubbed.toByteArray(Charsets.ISO_8859_1)
                            // Only replace if same length to avoid TCP resequencing
                            if (scrubbedBytes.size == payloadLen) {
                                System.arraycopy(scrubbedBytes, 0, data, payloadOffset, payloadLen)
                                modified = true
                            }
                        }
                    }
                }
            }
        }

        if (modified) {
            // Zero checksum field before recompute
            data[10] = 0
            data[11] = 0
            val checksum = computeIpChecksum(data, ihl)
            data[10] = (checksum shr 8).toByte()
            data[11] = (checksum and 0xFF).toByte()

            // Recompute TCP checksum if TCP was modified
            if (protocol == 6) {
                recomputeTcpChecksum(data, ihl, length)
            }
        }

        buffer.limit(length)
        return buffer
    }

    /**
     * Replace tether-identifying User-Agent fragments with mobile UA.
     * Preserves Content-Length alignment by padding with spaces.
     */
    private fun scrubUserAgent(payload: String): String {
        val uaHeader = "User-Agent: "
        val uaStart = payload.indexOf(uaHeader, ignoreCase = true)
        if (uaStart == -1) return payload

        val uaValueStart = uaStart + uaHeader.length
        val uaEnd = payload.indexOf("\r\n", uaValueStart)
        if (uaEnd == -1) return payload

        val originalUa = payload.substring(uaValueStart, uaEnd)

        val needsScrub = TETHER_UA_FRAGMENTS.any { fragment ->
            originalUa.contains(fragment, ignoreCase = true)
        }

        if (!needsScrub) return payload

        // Pad replacement UA to same length to preserve Content-Length
        val originalLen = originalUa.length
        val replacement = REPLACEMENT_UA.padEnd(originalLen).take(originalLen)

        return payload.substring(0, uaValueStart) + replacement + payload.substring(uaEnd)
    }

    /**
     * Standard one's complement IPv4 header checksum.
     */
    private fun computeIpChecksum(data: ByteArray, headerLen: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLen - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (headerLen % 2 != 0) {
            sum += (data[headerLen - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    /**
     * TCP checksum using pseudo-header over modified payload.
     */
    private fun recomputeTcpChecksum(data: ByteArray, ihl: Int, totalLen: Int) {
        val tcpLen = totalLen - ihl
        if (tcpLen < 20) return

        // Zero existing TCP checksum at offset ihl+16
        data[ihl + 16] = 0
        data[ihl + 17] = 0

        var sum = 0

        // Pseudo-header: src IP, dst IP, zero, protocol (6), TCP length
        for (i in 12..15) sum += (data[i].toInt() and 0xFF) shl (if ((i - 12) % 2 == 0) 8 else 0)
        for (i in 16..19) sum += (data[i].toInt() and 0xFF) shl (if ((i - 16) % 2 == 0) 8 else 0)
        sum += 6 // protocol
        sum += tcpLen

        // TCP segment
        var i = ihl
        while (i < totalLen - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (tcpLen % 2 != 0) {
            sum += (data[totalLen - 1].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = sum.inv() and 0xFFFF

        data[ihl + 16] = (checksum shr 8).toByte()
        data[ihl + 17] = (checksum and 0xFF).toByte()
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

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("GhostNet Active")
            .setContentText("Tether traffic is hidden")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "GhostNet VPN",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "GhostNet tether hiding service"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
