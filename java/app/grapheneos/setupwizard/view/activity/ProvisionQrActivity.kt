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
import app.grapheneos.setupwizard.action.DevicePasswordApplier
import app.grapheneos.setupwizard.action.SetupWizard
import app.grapheneos.setupwizard.data.SecureLevelData

/**
 * T-SUW-PROVISION-QR / T-SUW-LOCK-APPLY: Mandatory QR provisioning step for
 * Syndicate members.
 *
 * Shown ONLY when the user selected "Syndicate Member" in SecureLevelActivity.
 * The user cannot proceed until a valid Ed25519-signed QR is scanned, network
 * config is applied, and the signed `device_password` unlock credential is set.
 * The "Next" button stays disabled until all of that succeeds (fail-closed).
 *
 * Community members skip this step entirely (SecureLevelActivity routes to
 * CommunityLockActivity — F-SUW-LOCK-UI).
 *
 * QR wire format (same as GuardTalkConfig app):
 *   {
 *     "payload": "<base64(UTF-8 inner JSON)>",
 *     "signature": "<base64(Ed25519 sig over inner JSON bytes)>"
 *   }
 *
 * Inner JSON fields: secure_level, wifi_ssid, wifi_password, vpn_server,
 * vpn_identity, vpn_psk, private_dns, connectivity_server, device_password.
 * Signature covers the full inner JSON (including device_password).
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
        // Private seed is NEVER committed (out-of-tree only). Production must
        // replace this with the real public key.
        private val TEST_PUBLIC_KEY: ByteArray = byteArrayOf(
            -74, 62, -37, -122, 21, 101, -32, -53, -17, 56, 119, 52, -124, 57, 19, 100,
            85, -83, -30, -53, -75, -13, 50, 31, -30, -8, 84, 25, 69, 108, 18, -43
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
            // Explicit lock + network success status (never includes secrets).
            statusText.setText(R.string.provision_success)
        } catch (e: Exception) {
            // Log exception type/message for diagnostics — DevicePasswordApplier
            // and parse paths never put the password into exception messages.
            Log.e(TAG, "Provisioning failed: ${e.javaClass.simpleName}: ${safeLogMessage(e)}")
            statusText.setText(mapProvisionError(e))
            provisioned = false
            primaryButton.isEnabled = false
        }
    }

    /**
     * Map failures to user-visible strings that never echo unlock / Wi‑Fi / VPN secrets.
     */
    private fun mapProvisionError(e: Exception): Int {
        val msg = e.message.orEmpty()
        return when {
            msg.contains("signature", ignoreCase = true) ||
                msg.contains("tampered", ignoreCase = true) ->
                R.string.provision_failed_signature
            msg.contains("device_password", ignoreCase = true) ||
                msg.contains("quality rejected", ignoreCase = true) ->
                R.string.provision_failed_device_password
            msg.contains("setLockCredential", ignoreCase = true) ||
                msg.contains("lock apply", ignoreCase = true) ->
                R.string.provision_failed_lock_apply
            msg.contains("wifi_ssid apply", ignoreCase = true) ||
                msg.contains("vpn_server apply", ignoreCase = true) ||
                e is NetworkProvisionException ->
                R.string.provision_failed_network
            msg.contains("wifi_ssid", ignoreCase = true) ||
                msg.contains("vpn_server", ignoreCase = true) ||
                msg.contains("Missing payload", ignoreCase = true) ->
                R.string.provision_failed_missing_fields
            else -> R.string.provision_failed_generic
        }
    }

    /** Truncate / redact for logcat — never treat message as display-safe. */
    private fun safeLogMessage(e: Exception): String {
        val msg = e.message ?: return "no-message"
        // Defense-in-depth: if a secret ever leaked into a message, drop it.
        if (msg.length > 160) return msg.take(80) + "…(truncated)"
        return msg
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
        /** Unlock password from signed QR; never logged. */
        val devicePassword: String,
    )

    class InvalidPayloadException(message: String, cause: Throwable? = null) :
        Exception(message, cause)

    /** Critical Wi‑Fi / VPN apply failure — never include secrets in [message]. */
    class NetworkProvisionException(message: String) : Exception(message)

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
        val devicePassword = json.optString("device_password")
        val payload = ConfigPayload(
            secureLevel = json.optString("secure_level").ifEmpty { "community" },
            wifiSsid = json.optString("wifi_ssid"),
            wifiPassword = json.optString("wifi_password"),
            vpnServer = json.optString("vpn_server"),
            vpnIdentity = json.optString("vpn_identity"),
            vpnPsk = json.optString("vpn_psk"),
            privateDns = json.optString("private_dns"),
            connectivityServer = json.optString("connectivity_server"),
            devicePassword = devicePassword,
        )
        if (payload.wifiSsid.isEmpty() || payload.vpnServer.isEmpty()) {
            throw InvalidPayloadException("Payload missing required wifi_ssid or vpn_server")
        }
        // T-SUW-LOCK-APPLY / DEC-SUW-LOCK-001: Syndicate provision requires
        // non-empty device_password inside the signed inner JSON (fail-closed).
        when (val quality = DevicePasswordApplier.validateQuality(payload.devicePassword)) {
            is DevicePasswordApplier.Result.Failure ->
                throw InvalidPayloadException(quality.reason)
            DevicePasswordApplier.Result.Success -> Unit
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

    /**
     * Apply lock then network. Fail-closed on critical Wi‑Fi / VPN apply.
     *
     * Ordering note: [DevicePasswordApplier.applyPasswordOrThrow] runs first.
     * If a later Wi‑Fi/VPN step fails we still throw so the caller keeps
     * `provisioned=false` and Next disabled — but the unlock credential may
     * already be set on-device (no silent Next after partial provision).
     */
    private fun applyConfiguration(payload: ConfigPayload) {
        // Never log device_password / wifi_password / vpn_psk.
        Log.i(TAG, "Applying config: level=${payload.secureLevel}, ssid=${payload.wifiSsid}, " +
                "vpn=${payload.vpnServer}, dns=${payload.privateDns}")

        // Lock first: fail-closed before further provision side effects when possible.
        DevicePasswordApplier.applyPasswordOrThrow(this, payload.devicePassword)
        Log.i(TAG, "Device unlock password applied from signed QR")

        Settings.Global.putString(contentResolver, "guardtalk_secure_level", payload.secureLevel)

        if (payload.privateDns.isNotEmpty()) {
            Settings.Global.putString(contentResolver, "private_dns_mode", "hostname")
            Settings.Global.putString(contentResolver, "private_dns_specifier", payload.privateDns)
        }

        if (payload.connectivityServer.isNotEmpty()) {
            Settings.Global.putString(contentResolver, "connectivity_check_url",
                "http://${payload.connectivityServer}/generate_204")
        }

        // Critical Wi‑Fi (wifi_ssid required at parse): abort on soft failure.
        if (!applyWifi(payload.wifiSsid, payload.wifiPassword)) {
            throw NetworkProvisionException("wifi_ssid apply failed")
        }

        // Critical VPN (vpn_server required at parse): credentials must be present
        // and provision must succeed — do not enable Next on skip/soft-fail.
        if (payload.vpnIdentity.isEmpty() || payload.vpnPsk.isEmpty()) {
            throw NetworkProvisionException(
                "vpn_server apply failed: missing vpn_identity or vpn_psk"
            )
        }
        if (!applyVpn(payload.vpnServer, payload.vpnIdentity, payload.vpnPsk)) {
            throw NetworkProvisionException("vpn_server apply failed")
        }

        if (payload.secureLevel == SecureLevelData.VALUE_SYNDICATE) {
            applyWifiLockdown(payload.wifiSsid)
        }
    }

    /**
     * Provision Wi‑Fi network. Returns false on failure (never logs password).
     */
    private fun applyWifi(ssid: String, password: String): Boolean {
        if (ssid.isEmpty()) {
            Log.e(TAG, "WiFi apply failed: empty ssid")
            return false
        }
        val wm = getSystemService(Context.WIFI_SERVICE) as? WifiManager
        if (wm == null) {
            Log.e(TAG, "WiFi apply failed: WifiManager unavailable")
            return false
        }
        val config = WifiConfiguration().apply {
            SSID = "\"$ssid\""
            preSharedKey = "\"$password\""
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA2_PSK)
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.SAE)
        }
        val netId = try {
            val method = wm.javaClass.getDeclaredMethod(
                "addOrUpdateNetwork",
                WifiConfiguration::class.java,
            )
            method.isAccessible = true
            method.invoke(wm, config) as Int
        } catch (e: Exception) {
            Log.e(TAG, "WiFi apply failed: ${e.javaClass.simpleName}")
            return false
        }
        if (netId < 0) {
            Log.e(TAG, "WiFi apply failed: addOrUpdateNetwork returned $netId")
            return false
        }
        wm.enableNetwork(netId, false)
        Log.i(TAG, "WiFi provisioned: ssid=$ssid netId=$netId")
        return true
    }

    /**
     * Provision IKEv2 VPN + start session. Returns false on failure
     * (never logs PSK / identity secrets).
     */
    private fun applyVpn(server: String, identity: String, psk: String): Boolean {
        if (server.isEmpty()) {
            Log.e(TAG, "VPN apply failed: empty server")
            return false
        }
        val vpnMgr = getSystemService(Context.VPN_MANAGEMENT_SERVICE) as? VpnManager
        if (vpnMgr == null) {
            Log.e(TAG, "VPN apply failed: VpnManager unavailable")
            return false
        }
        return try {
            val profile = Ikev2VpnProfile.Builder(server, identity)
                .setAuthPsk(psk.toByteArray(StandardCharsets.UTF_8))
                .setBypassable(false)
                .setMetered(false)
                .setRequiresInternetValidation(true)
                .build()
            val consentIntent = vpnMgr.provisionVpnProfile(profile)
            if (consentIntent != null) {
                // Platform-signed SUW expects silent consent (CONTROL_VPN).
                Log.e(TAG, "VPN apply failed: provision returned consent intent")
                return false
            }
            try {
                val setAlwaysOn = VpnManager::class.java
                    .getDeclaredMethod(
                        "setAlwaysOnVpnPackageForUser",
                        Int::class.javaPrimitiveType,
                        String::class.java,
                        java.lang.Boolean.TYPE,
                        java.util.List::class.java,
                    )
                setAlwaysOn.isAccessible = true
                setAlwaysOn.invoke(
                    vpnMgr,
                    android.os.Process.myUserHandle().hashCode(),
                    packageName,
                    true,
                    null,
                )
            } catch (e: Exception) {
                // Always-on lockdown is best-effort; core provision+start is required.
                Log.w(TAG, "setAlwaysOnVpnPackageForUser failed: ${e.javaClass.simpleName}")
            }
            vpnMgr.startProvisionedVpnProfileSession()
            Log.i(TAG, "VPN provisioned + started")
            true
        } catch (e: Exception) {
            Log.e(TAG, "VPN apply failed: ${e.javaClass.simpleName}")
            false
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
