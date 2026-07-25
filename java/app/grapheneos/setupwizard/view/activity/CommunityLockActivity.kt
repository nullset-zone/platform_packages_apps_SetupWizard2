package app.grapheneos.setupwizard.view.activity

import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import app.grapheneos.setupwizard.R
import app.grapheneos.setupwizard.action.DevicePasswordApplier
import app.grapheneos.setupwizard.action.SetupWizard

/**
 * F-SUW-LOCK-UI / DEC-SUW-LOCK-001: Community interactive unlock password page.
 *
 * Launched directly by [SecureLevelActivity] for Community (not listed in
 * [SetupWizard] primaryUserActivities — same insert pattern as [ProvisionQrActivity]).
 * Password-only policy: no PIN/pattern UI. Wizard advances only after
 * [DevicePasswordApplier.applyPassword] succeeds.
 */
class CommunityLockActivity : SetupWizardActivity(
    R.layout.community_lock_activity,
    R.drawable.baseline_security_glif,
    R.string.community_lock_title,
    R.string.community_lock_desc,
) {
    private lateinit var passwordField: EditText
    private lateinit var confirmField: EditText
    private lateinit var statusText: TextView

    companion object {
        private const val TAG = "CommunityLockActivity"
    }

    override fun bindViews() {
        passwordField = requireViewById(R.id.community_lock_password)
        confirmField = requireViewById(R.id.community_lock_password_confirm)
        statusText = requireViewById(R.id.community_lock_status_text)

        primaryButton.setText(this, R.string.next)
        primaryButton.isEnabled = false
        statusText.setText(R.string.community_lock_pending)
    }

    override fun setupActions() {
        val refreshNextEnabled = TextWatcher {
            primaryButton.isEnabled =
                passwordField.text.isNotEmpty() && confirmField.text.isNotEmpty()
        }
        passwordField.addTextChangedListener(refreshNextEnabled)
        confirmField.addTextChangedListener(refreshNextEnabled)

        passwordField.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_NEXT) {
                confirmField.requestFocus()
                true
            } else {
                false
            }
        }
        confirmField.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE && primaryButton.isEnabled) {
                tryApplyAndAdvance()
                true
            } else {
                false
            }
        }

        primaryButton.setOnClickListener {
            tryApplyAndAdvance()
        }
    }

    private fun tryApplyAndAdvance() {
        val password = passwordField.text?.toString().orEmpty()
        val confirm = confirmField.text?.toString().orEmpty()

        if (password != confirm) {
            showSafeError(R.string.community_lock_mismatch)
            clearSecretFields()
            return
        }

        when (val result = DevicePasswordApplier.applyPassword(this, password)) {
            DevicePasswordApplier.Result.Success -> {
                clearSecretFields()
                statusText.setText(R.string.community_lock_success)
                Log.i(TAG, "Community device unlock password applied")
                // Advance from SecureLevel's position → DateTime (not in primary list).
                SetupWizard.next(this, SecureLevelActivity::class.java)
            }
            is DevicePasswordApplier.Result.Failure -> {
                showSafeError(mapFailureToStringRes(result.reason))
                clearSecretFields()
                // Log reason codes only — never the password.
                Log.e(TAG, "Community lock apply failed: ${result.reason}")
            }
        }
    }

    private fun mapFailureToStringRes(reason: String): Int {
        return when {
            reason.contains("empty", ignoreCase = true) ||
                reason.contains("missing", ignoreCase = true) ->
                R.string.community_lock_empty
            reason.contains("shorter", ignoreCase = true) ->
                R.string.community_lock_too_short
            reason.contains("quality", ignoreCase = true) ->
                R.string.community_lock_quality_rejected
            else -> R.string.community_lock_apply_failed
        }
    }

    private fun showSafeError(messageRes: Int) {
        statusText.setText(messageRes)
        primaryButton.isEnabled = false
    }

    private fun clearSecretFields() {
        passwordField.text?.clear()
        confirmField.text?.clear()
        passwordField.requestFocus()
    }

    private fun TextWatcher(onChanged: () -> Unit): TextWatcher {
        return object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                onChanged()
            }
        }
    }
}
