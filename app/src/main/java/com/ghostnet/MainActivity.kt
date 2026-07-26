package com.ghostnet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.ghostnet.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startGhostNet()
        } else {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val running = intent.getBooleanExtra("running", false)
            updateUi(running)
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
            } else {
                requestVpnPermission()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(stateReceiver, IntentFilter("com.ghostnet.VPN_STATE"), RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(stateReceiver, IntentFilter("com.ghostnet.VPN_STATE"))
        }
        updateUi(GhostVpnService.isRunning)
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(stateReceiver)
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnLauncher.launch(intent)
        } else {
            startGhostNet()
        }
    }

    private fun startGhostNet() {
        val intent = Intent(this, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_START
        }
        startForegroundService(intent)
    }

    private fun stopGhostNet() {
        val intent = Intent(this, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun updateUi(running: Boolean) {
        binding.btnToggle.text = if (running) "Stop GhostNet" else "Start GhostNet"
        binding.tvStatus.text = if (running) "● Active — traffic hidden" else "○ Inactive"
        binding.tvStatus.setTextColor(
            getColor(if (running) android.R.color.holo_green_light else android.R.color.darker_gray)
        )
        binding.tvTtlInfo.text = if (running) "TTL normalized to 64\nUser-Agent scrubbed\nDNS → 1.1.1.1" else ""
    }
}
