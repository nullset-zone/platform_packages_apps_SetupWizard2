package app.grapheneos.setupwizard.action

import android.content.Context
import android.os.UserHandle
import android.util.Log
import com.android.internal.widget.LockPatternUtils
import com.android.internal.widget.LockscreenCredential

/**
 * Shared SUW helper to establish a device unlock **password** (password-only policy).
 *
 * Used by Syndicate [app.grapheneos.setupwizard.view.activity.ProvisionQrActivity]
 * (signed QR `device_password`) and by Community lock UI ([F-SUW-LOCK-UI]) once
 * dispatched. Never logs plaintext secrets; zeroes [LockscreenCredential] buffers
 * after use.
 *
 * Credential type is always [LockscreenCredential.createPassword] /
 * `CREDENTIAL_TYPE_PASSWORD` — PIN/pattern are not accepted (see
 * `vendor/guardtalk/docs/PASSWORD_ONLY_LOCK_POLICY.md`).
 */
object DevicePasswordApplier {
    private const val TAG = "DevicePasswordApplier"

    /** Platform minimum for password credentials ([LockPatternUtils.MIN_LOCK_PASSWORD_SIZE]). */
    const val MIN_PASSWORD_LENGTH: Int = LockPatternUtils.MIN_LOCK_PASSWORD_SIZE

    sealed class Result {
        data object Success : Result()
        data class Failure(val reason: String) : Result()
    }

    /**
     * Quality gate (fail-closed): non-null, non-blank after trim, min length.
     * Does not log or retain the secret.
     */
    fun validateQuality(password: CharSequence?): Result {
        if (password == null) {
            return Result.Failure("device_password missing")
        }
        val trimmedLength = password.trim().length
        if (trimmedLength == 0) {
            return Result.Failure("device_password empty")
        }
        if (trimmedLength < MIN_PASSWORD_LENGTH) {
            return Result.Failure(
                "device_password shorter than $MIN_PASSWORD_LENGTH characters"
            )
        }
        return Result.Success
    }

    /**
     * Apply [password] as the primary unlock credential for [userId].
     *
     * Expects no existing lock (SUW / initial set): saved credential is
     * [LockscreenCredential.createNone]. Fail-closed on quality or LSS errors.
     */
    @JvmOverloads
    fun applyPassword(
        context: Context,
        password: CharSequence?,
        userId: Int = UserHandle.myUserId(),
    ): Result {
        when (val quality = validateQuality(password)) {
            is Result.Failure -> return quality
            Result.Success -> Unit
        }
        // Trimmed copy for LSS only; never logged.
        val trimmed = password!!.trim().toString()
        var newCredential: LockscreenCredential? = null
        var savedCredential: LockscreenCredential? = null
        return try {
            newCredential = LockscreenCredential.createPassword(trimmed)
            savedCredential = LockscreenCredential.createNone()
            newCredential.validateBasicRequirements()
            val utils = LockPatternUtils(context)
            val ok = utils.setLockCredential(newCredential, savedCredential, userId)
            if (!ok) {
                Log.e(TAG, "setLockCredential returned false (userId=$userId)")
                Result.Failure("setLockCredential failed")
            } else {
                Log.i(TAG, "Device unlock password applied (userId=$userId)")
                Result.Success
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "Device password apply denied: ${e.javaClass.simpleName}")
            Result.Failure("lock apply denied")
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Device password rejected: ${e.javaClass.simpleName}")
            Result.Failure("device_password quality rejected")
        } catch (e: Exception) {
            Log.e(TAG, "Device password apply failed: ${e.javaClass.simpleName}")
            Result.Failure("lock apply failed")
        } finally {
            newCredential?.zeroize()
            savedCredential?.zeroize()
        }
    }

    /** Fail-closed wrapper that throws [IllegalStateException] on [Result.Failure]. */
    @JvmOverloads
    fun applyPasswordOrThrow(
        context: Context,
        password: CharSequence?,
        userId: Int = UserHandle.myUserId(),
    ) {
        when (val result = applyPassword(context, password, userId)) {
            is Result.Failure -> throw IllegalStateException(result.reason)
            Result.Success -> Unit
        }
    }
}
