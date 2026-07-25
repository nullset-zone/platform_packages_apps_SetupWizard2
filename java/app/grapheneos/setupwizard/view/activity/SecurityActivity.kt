package app.grapheneos.setupwizard.view.activity

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import app.grapheneos.setupwizard.action.SecurityActions
import app.grapheneos.setupwizard.action.SetupWizard
import app.grapheneos.setupwizard.data.SecurityData

class SecurityActivity : ProxyActivity() {

    companion object {
        private const val TAG = "SecurityActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isDeviceSecure() == true) {
            Log.d(TAG, "onCreate: skipping, device already secure")
            finish()
            SetupWizard.next(this)
            return
        }
        // GuardTalk (F-WIZ-FP / T-SUW-LOCK-BACKSTOP): fingerprint HAL excised and
        // no face biometric — BIOMETRIC_ENROLL has no target. Do not advance the
        // wizard when the device still lacks a lock credential (fail-closed).
        // Password-only policy unchanged; do not fall back to PIN/pattern setup.
        if (!hasBiometricFeature()) {
            Log.w(
                TAG,
                "onCreate: refusing advance: no fingerprint/face feature and " +
                    "device not secure"
            )
            setMovingForward()
            finish()
            // Deliberately omit SetupWizard.next — M1 secure backstop.
            return
        }
    }

    private fun hasBiometricFeature(): Boolean {
        val pm = packageManager
        return pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) ||
                pm.hasSystemFeature(PackageManager.FEATURE_FACE)
    }

    override fun launchActual() {
        SecurityActions.launchSetup(this)
    }

    private fun isDeviceSecure(): Boolean? {
        return SecurityData.isDeviceSecure.value
    }

    override fun handleResult(resultCode: Int, data: Intent?) {
        Log.d(TAG, "handleResult: $resultCode")
        SecurityActions.refreshSecurityStatus()
        if (isDeviceSecure() == true) finish()
        else setMovingForward()
        SecurityActions.handleResult(this, resultCode)
    }
}
