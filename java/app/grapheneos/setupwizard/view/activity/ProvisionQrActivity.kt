package app.grapheneos.setupwizard.view.activity

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.TextView
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import android.provider.Settings
import android.net.Ikev2VpnProfile
import android.net.VpnManager
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.net.wifi.WifiSsid
import android.app.admin.WifiSsidPolicy
import android.os.UserManager
import java.nio.charset.StandardCharsets
import app.grapheneos.setupwizard.R
import app.grapheneos.setupwizard.action.SetupWizard
import app.grapheneos.setupwizard.data.SecureLevelData

/**
 * T-SUW-PROVISION-QR: Mandatory QR provisioning step for Syndicate members.
 *
 * Shown ONLY when the user selected "Syndicate Member" in SecureLevelActivity.
 * The user cannot proceed to the Home screen until a valid Ed25519-signed QR
 * is scanned and the configuration applied. The "Next" button is disabled
 * until provisioning succeeds.
 *
 * Community members skip this step entirely (SecureLevelActivity calls
 * SetupWizard.next() directly for Community, bypassing this activity).
 *
 * QR wire format (same as GuardTalkConfig app):
 *   {
 *     "payload": "<base64(UTF-8 inner JSON)>",
 *     "signature": "<base64(Ed25519 sig over inner JSON bytes)>"
 *   }
 *
 * Inner JSON fields: secure_level, wifi_ssid, wifi_password, vpn_server,
 * vpn_identity, vpn_psk, private_dns, connectivity_server.
 */
class ProvisionQrActivity : SetupWizardActivity(
    R.layout.provision_qr_activity,
    R.drawable.baseline_security_glif,
    R.string.provision_qr_title,
    R.string.provision_qr_desc,
) {
    private lateinit var scanButton: Button
    private lateinit var statusText: TextView
    private var provisioned = false

    companion object {
        private const val TAG = "ProvisionQrActivity"
        private const val REQUEST_SCAN = 0x5151

        // Ed25519 test public key — MUST match QrPayloadParser in GuardTalkConfig.
        // Production deployments must replace this with the real public key.
        private val TEST_PUBLIC_KEY: ByteArray = byteArrayOf(
            -3, 5, 119, -128, 39, -86, -3, 92, -8, -82, 60, -109, 9, 39, -98, -30,
            103, 102, 101, -72, 108, 120, -47, -107, -80, 78, -9, 14, -113, -89, -38, 74
        )
    }

    override fun bindViews() {
        scanButton = requireViewById(R.id.provision_scan_button)
        statusText = requireViewById(R.id.provision_status_text)

        scanButton.setText(R.string.scan_qr_code)
        primaryButton.setText(this, R.string.next)
        // Disabled until a valid QR is scanned & applied.
        primaryButton.isEnabled = false
    }

    override fun setupActions() {
        scanButton.setOnClickListener {
            launchQrScanner()
        }
        primaryButton.setOnClickListener {
            if (provisioned) {
                // Advance from SecureLevel's position → DateTimeActivity.
                // (ProvisionQrActivity is intentionally not in the wizard list;
                // it's launched directly by SecureLevelActivity for Syndicate.)
                SetupWizard.next(this, SecureLevelActivity::class.java)
            }
        }
    }

    private fun launchQrScanner() {
        val intent = Intent("com.google.zxing.client.android.SCAN").apply {
            putExtra("SCAN_MODE", "QR_CODE_MODE")
            putExtra("BEEP_ENABLED", true)
        }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, REQUEST_SCAN)
        } catch (e: android.content.ActivityNotFoundException) {
            Log.w(TAG, "No QR scanner installed")
            statusText.setText(R.string.no_qr_scanner)
        }
    }

    @Deprecated("Deprecated in super")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_SCAN) return

        if (resultCode != Activity.RESULT_OK) {
            statusText.setText(R.string.qr_scan_cancelled)
            return
        }

        val rawQr = data?.getStringExtra("SCAN_RESULT")
        if (rawQr.isNullOrBlank()) {
            statusText.setText(R.string.qr_empty)
            return
        }

        try {
            val payload = parseAndVerify(rawQr)
            applyConfiguration(payload)
            provisioned = true
            primaryButton.isEnabled = true
            statusText.setText(R.string.provision_success)
        } catch (e: Exception) {
            Log.e(TAG, "Provisioning failed", e)
            statusText.text = getString(R.string.provision_failed, e.message ?: "unknown")
            provisioned = false
            primaryButton.isEnabled = false
        }
    }

    // ── QR parsing + Ed25519 verification (mirrors GuardTalkConfig.QrPayloadParser) ──

    data class ConfigPayload(
        val secureLevel: String,
        val wifiSsid: String,
        val wifiPassword: String,
        val vpnServer: String,
        val vpnIdentity: String,
        val vpnPsk: String,
        val privateDns: String,
        val connectivityServer: String,
    )

    class InvalidPayloadException(message: String, cause: Throwable? = null) :
        Exception(message, cause)

    private fun parseAndVerify(qrText: String): ConfigPayload {
        val envelope = qrText.trim().removePrefix("guardtalk://").trim()
        val outer = JSONObject(envelope)

        val payloadB64 = outer.optString("payload")
        val signatureB64 = outer.optString("signature")
        if (payloadB64.isEmpty() || signatureB64.isEmpty()) {
            throw InvalidPayloadException("Missing payload/signature — unsigned QR rejected")
        }

        val payloadBytes = Base64.decode(payloadB64, Base64.NO_WRAP)
        val signatureBytes = Base64.decode(signatureB64, Base64.NO_WRAP)

        verifyEd25519(payloadBytes, signatureBytes)

        val json = JSONObject(String(payloadBytes, Charsets.UTF_8))
        val payload = ConfigPayload(
            secureLevel = json.optString("secure_level").ifEmpty { "community" },
            wifiSsid = json.optString("wifi_ssid"),
            wifiPassword = json.optString("wifi_password"),
            vpnServer = json.optString("vpn_server"),
            vpnIdentity = json.optString("vpn_identity"),
            vpnPsk = json.optString("vpn_psk"),
            privateDns = json.optString("private_dns"),
            connectivityServer = json.optString("connectivity_server"),
        )
        if (payload.wifiSsid.isEmpty() || payload.vpnServer.isEmpty()) {
            throw InvalidPayloadException("Payload missing required wifi_ssid or vpn_server")
        }
        return payload
    }

    private fun verifyEd25519(message: ByteArray, signature: ByteArray) {
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(encodeSpki(TEST_PUBLIC_KEY)))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(publicKey)
        verifier.update(message)
        if (!verifier.verify(signature)) {
            throw InvalidPayloadException("Ed25519 signature does not verify — tampered QR rejected")
        }
    }

    private fun encodeSpki(rawPubKey: ByteArray): ByteArray {
        require(rawPubKey.size == 32) { "Ed25519 public key must be 32 bytes" }
        val spki = ByteArray(44)
        spki[0] = 0x30; spki[1] = 0x2A
        spki[2] = 0x30; spki[3] = 0x05
        spki[4] = 0x06; spki[5] = 0x03
        spki[6] = 0x2B; spki[7] = 0x65; spki[8] = 0x70
        spki[9] = 0x03; spki[10] = 0x21
        spki[11] = 0x00
        System.arraycopy(rawPubKey, 0, spki, 12, 32)
        return spki
    }

    // ── Configuration application (mirrors GuardTalkConfig.ConfigApplier) ──

    private fun applyConfiguration(payload: ConfigPayload) {
        Log.i(TAG, "Applying config: level=${payload.secureLevel}, ssid=${payload.wifiSsid}, " +
                "vpn=${payload.vpnServer}, dns=${payload.privateDns}")

        Settings.Global.putString(contentResolver, "guardtalk_secure_level", payload.secureLevel)

        if (payload.privateDns.isNotEmpty()) {
            Settings.Global.putString(contentResolver, "private_dns_mode", "hostname")
            Settings.Global.putString(contentResolver, "private_dns_specifier", payload.privateDns)
        }

        if (payload.connectivityServer.isNotEmpty()) {
            Settings.Global.putString(contentResolver, "connectivity_check_url",
                "http://${payload.connectivityServer}/generate_204")
        }

        if (payload.wifiSsid.isNotEmpty()) {
            applyWifi(payload.wifiSsid, payload.wifiPassword)
        }

        if (payload.vpnServer.isNotEmpty() && payload.vpnIdentity.isNotEmpty()
            && payload.vpnPsk.isNotEmpty()) {
            applyVpn(payload.vpnServer, payload.vpnIdentity, payload.vpnPsk)
        }

        if (payload.secureLevel == SecureLevelData.VALUE_SYNDICATE) {
            applyWifiLockdown(payload.wifiSsid)
        }
    }

    private fun applyWifi(ssid: String, password: String) {
        val wm = getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        val config = WifiConfiguration().apply {
            SSID = "\"$ssid\""
            preSharedKey = "\"$password\""
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA2_PSK)
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.SAE)
        }
        val netId = try {
            val method = wm.javaClass.getDeclaredMethod("addOrUpdateNetwork", WifiConfiguration::class.java)
            method.isAccessible = true
            method.invoke(wm, config) as Int
        } catch (e: Exception) { -999 }
        if (netId >= 0) {
            wm.enableNetwork(netId, false)
            Log.i(TAG, "WiFi provisioned: ssid=$ssid netId=$netId")
        }
    }

    private fun applyVpn(server: String, identity: String, psk: String) {
        val vpnMgr = getSystemService(Context.VPN_MANAGEMENT_SERVICE) as? VpnManager ?: return
        try {
            val profile = Ikev2VpnProfile.Builder(server, identity)
                .setAuthPsk(psk.toByteArray(StandardCharsets.UTF_8))
                .setBypassable(false)
                .setMetered(false)
                .setRequiresInternetValidation(true)
                .build()
            val consentIntent = vpnMgr.provisionVpnProfile(profile)
            if (consentIntent == null) {
                try {
                    val setAlwaysOn = VpnManager::class.java
                        .getDeclaredMethod("setAlwaysOnVpnPackageForUser",
                            Int::class.javaPrimitiveType, String::class.java,
                            java.lang.Boolean.TYPE, java.util.List::class.java)
                    setAlwaysOn.isAccessible = true
                    setAlwaysOn.invoke(vpnMgr, android.os.Process.myUserHandle().hashCode(),
                        packageName, true, null)
                } catch (e: Exception) {
                    Log.w(TAG, "setAlwaysOnVpnPackageForUser failed: ${e.message}")
                }
                vpnMgr.startProvisionedVpnProfileSession()
                Log.i(TAG, "VPN provisioned + started")
            }
        } catch (e: Exception) {
            Log.e(TAG, "VPN provisioning failed: ${e.message}")
        }
    }

    private fun applyWifiLockdown(gmpSsid: String) {
        try {
            val wm = getSystemService(Context.WIFI_SERVICE) as? WifiManager
            if (wm != null) {
                val m = WifiManager::class.java.getDeclaredMethod("setWifiSsidPolicy",
                    WifiSsidPolicy::class.java)
                m.isAccessible = true
                val ssidSet = setOf(wifiSsidFromUtf8(gmpSsid))
                val policy = WifiSsidPolicy(WifiSsidPolicy.WIFI_SSID_POLICY_TYPE_ALLOWLIST, ssidSet)
                m.invoke(wm, policy)
                Log.i(TAG, "WiFi SSID allowlist set: {$gmpSsid}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "setWifiSsidPolicy failed: ${e.message}")
        }

        val um = getSystemService(Context.USER_SERVICE) as? UserManager ?: return
        for (r in listOf(UserManager.DISALLOW_ADD_WIFI_CONFIG,
                "no_config_wifi_shared", "no_config_wifi_private")) {
            try { um.setUserRestriction(r, true) }
            catch (e: Exception) { Log.w(TAG, "setUserRestriction($r) failed: ${e.message}") }
        }
        Log.i(TAG, "WiFi user restrictions applied")
    }

    private fun wifiSsidFromUtf8(ssid: String): WifiSsid {
        val m = WifiSsid::class.java.getDeclaredMethod("fromUtf8Text", CharSequence::class.java)
        m.isAccessible = true
        return m.invoke(null, ssid) as WifiSsid
    }
}
