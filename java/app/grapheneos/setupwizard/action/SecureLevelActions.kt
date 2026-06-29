package app.grapheneos.setupwizard.action

import android.app.Activity
import android.content.Context
import android.provider.Settings
import android.util.Log
import app.grapheneos.setupwizard.data.SecureLevelData

object SecureLevelActions {
    private const val TAG = "SecureLevelActions"

    fun loadSelection(context: Context): String {
        val current = Settings.Global.getString(
            context.contentResolver,
            SecureLevelData.KEY_SECURE_LEVEL
        ) ?: SecureLevelData.VALUE_SYNDICATE
        SecureLevelData.selectedLevel.value = current
        return current
    }

    fun persistSelection(activity: Activity, value: String) {
        Log.d(TAG, "persistSelection: $value")
        Settings.Global.putString(
            activity.contentResolver,
            SecureLevelData.KEY_SECURE_LEVEL,
            value
        )
        SecureLevelData.selectedLevel.value = value
    }
}
