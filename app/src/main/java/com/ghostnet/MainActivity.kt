package com.ghostnet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.ghostnet.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var connecting = false

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        connecting = false
        if (result.resultCode == RESULT_OK) {
            startGhostNet()
        } else {
            updateUi(false)
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            connecting = false
            updateUi(intent.getBooleanExtra("running", false))
        }
    }

    private val statsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val bytesIn = intent.getLongExtra("bytesIn", 0)
            val bytesOut = intent.getLongExtra("bytesOut", 0)
            val packets = intent.getLongExtra("packets", 0)
            val ttl = intent.getLongExtra("ttlRewrites", 0)
            val ua = intent.getLongExtra("uaScrubs", 0)
            updateStats(bytesIn, bytesOut, packets, ttl, ua)
        }
    }

    private val errorReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            connecting = false
            updateUi(false)
            Toast.makeText(this@MainActivity, intent.getStringExtra("message"), Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        updateUi(GhostVpnService.isRunning)

        binding.btnToggle.setOnClickListener {
            if (GhostVpnService.isRunning) {
                stopGhostNet()
            } else if (!connecting) {
                connecting = true
                setConnectingState()
                requestVpnPermission()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) RECEIVER_NOT_EXPORTED else 0
        registerReceiver(stateReceiver, IntentFilter("com.ghostnet.VPN_STATE"), flags)
        registerReceiver(statsReceiver, IntentFilter("com.ghostnet.VPN_STATS"), flags)
        registerReceiver(errorReceiver, IntentFilter("com.ghostnet.VPN_ERROR"), flags)
        updateUi(GhostVpnService.isRunning)
        if (GhostVpnService.isRunning) updateStats(
            GhostVpnService.bytesIn.get(),
            GhostVpnService.bytesOut.get(),
            GhostVpnService.packetsProcessed.get(),
            GhostVpnService.ttlRewrites.get(),
            GhostVpnService.uaScrubs.get()
        )
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(stateReceiver)
        unregisterReceiver(statsReceiver)
        unregisterReceiver(errorReceiver)
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnLauncher.launch(intent) else { connecting = false; startGhostNet() }
    }

    private fun startGhostNet() {
        startForegroundService(Intent(this, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_START
        })
    }

    private fun stopGhostNet() {
        startService(Intent(this, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_STOP
        })
        updateUi(false)
    }

    private fun setConnectingState() {
        binding.btnToggle.text = "Connecting..."
        binding.btnToggle.isEnabled = false
        binding.tvStatus.text = "● Connecting"
        binding.tvStatus.setTextColor(getColor(android.R.color.holo_orange_light))
        binding.progressBar.visibility = View.VISIBLE
        binding.statsCard.visibility = View.GONE
    }

    private fun updateUi(running: Boolean) {
        connecting = false
        binding.btnToggle.isEnabled = true
        binding.progressBar.visibility = View.GONE

        if (running) {
            binding.btnToggle.text = "Stop GhostNet"
            binding.tvStatus.text = "● Active — traffic hidden"
            binding.tvStatus.setTextColor(getColor(android.R.color.holo_green_light))
            binding.statsCard.visibility = View.VISIBLE
        } else {
            binding.btnToggle.text = "Start GhostNet"
            binding.tvStatus.text = "○ Inactive"
            binding.tvStatus.setTextColor(getColor(android.R.color.darker_gray))
            binding.statsCard.visibility = View.GONE
            clearStats()
        }
    }

    private fun updateStats(bytesIn: Long, bytesOut: Long, packets: Long, ttl: Long, ua: Long) {
        binding.tvBytesIn.text = "↓ ${formatBytes(bytesIn)}"
        binding.tvBytesOut.text = "↑ ${formatBytes(bytesOut)}"
        binding.tvPackets.text = "$packets packets"
        binding.tvTtlRewrites.text = "$ttl TTL rewrites"
        binding.tvUaScrubs.text = "$ua UA scrubs"
    }

    private fun clearStats() {
        binding.tvBytesIn.text = "↓ 0B"
        binding.tvBytesOut.text = "↑ 0B"
        binding.tvPackets.text = "0 packets"
        binding.tvTtlRewrites.text = "0 TTL rewrites"
        binding.tvUaScrubs.text = "0 UA scrubs"
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "${bytes}B"
            bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)}KB"
            bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))}MB"
            else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))}GB"
        }
    }
}
