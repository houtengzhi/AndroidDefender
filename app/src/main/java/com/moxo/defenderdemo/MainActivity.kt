package com.moxo.defenderdemo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import com.moxo.defender.DefenderUtil

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val tv = findViewById<TextView>(R.id.tv_message)
        DefenderUtil.detectFrida(object : DefenderUtil.OnDetectFridaListener {
            override fun onDetected(detected: Boolean) {
                Log.d("DefenderDemo", "detected=$detected")
                tv.text = if (detected) "Frida detected!" else "No frida detected."
            }

        })
    }
}