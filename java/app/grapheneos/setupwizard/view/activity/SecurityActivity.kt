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
        // GuardTalk (F-WIZ-FP): when the fingerprint HAL is excised and no face
        // biometric is available, the BIOMETRIC_ENROLL intent has no target and
        // would crash/hang. Skip forward to the next wizard step instead. This
        // mirrors the existing skip pattern (cf. UpdaterSecurityPreviewActivity).
        if (!hasBiometricFeature()) {
            Log.d(TAG, "onCreate: skipping, no fingerprint/face feature present")
            finish()
            SetupWizard.next(this)
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
