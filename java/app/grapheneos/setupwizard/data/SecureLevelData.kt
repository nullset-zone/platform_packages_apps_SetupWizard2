package app.grapheneos.setupwizard.data

import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel

object SecureLevelData : ViewModel() {

    const val KEY_SECURE_LEVEL = "guardtalk_secure_level"
    const val VALUE_SYNDICATE = "syndicate"
    const val VALUE_COMMUNITY = "community"

    val selectedLevel = MutableLiveData<String>()
}
