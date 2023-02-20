package com.yechy.defender

/**
 *
 * Created by cloud on 2022/11/7.
 */
class DefenderUtil {

    companion object {
        // Used to load the 'defender' library on application startup.
        init {
            System.loadLibrary("defender")
        }

        fun detectFrida(listener: OnDetectFridaListener) {
            nativeDetectFrida(listener)
        }

        private external fun nativeDetectFrida(listener: OnDetectFridaListener)

    }

    interface OnDetectFridaListener {
        fun onDetected(detected: Boolean)
    }

}