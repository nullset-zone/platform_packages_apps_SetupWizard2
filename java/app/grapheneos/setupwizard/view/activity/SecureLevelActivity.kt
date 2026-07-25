package app.grapheneos.setupwizard.view.activity

import android.content.Intent
import android.widget.RadioGroup
import app.grapheneos.setupwizard.R
import app.grapheneos.setupwizard.action.SecureLevelActions
import app.grapheneos.setupwizard.data.SecureLevelData

class SecureLevelActivity : SetupWizardActivity(
    R.layout.secure_level_activity,
    R.drawable.baseline_security_glif,
    R.string.secure_level_title,
    R.string.secure_level_desc,
) {
    private lateinit var radioGroup: RadioGroup

    override fun bindViews() {
        radioGroup = requireViewById(R.id.secure_level_radio_group)
        primaryButton.setText(this, R.string.next)

        val initial = SecureLevelActions.loadSelection(this)
        val checkedId = when (initial) {
            SecureLevelData.VALUE_COMMUNITY -> R.id.secure_level_community
            else -> R.id.secure_level_syndicate
        }
        radioGroup.check(checkedId)
    }

    override fun setupActions() {
        primaryButton.setOnClickListener {
            val value = when (radioGroup.checkedRadioButtonId) {
                R.id.secure_level_community -> SecureLevelData.VALUE_COMMUNITY
                else -> SecureLevelData.VALUE_SYNDICATE
            }
            SecureLevelActions.persistSelection(this, value)
            if (value == SecureLevelData.VALUE_SYNDICATE) {
                // T-SUW-PROVISION-QR: Syndicate members must scan the GMP Router
                // QR before they can proceed. Community members skip QR.
                startActivity(Intent(this, ProvisionQrActivity::class.java))
                finish()
            } else {
                // F-SUW-LOCK-UI / DEC-SUW-LOCK-001: Community sets unlock password
                // on CommunityLockActivity (not in primaryUserActivities). Do not
                // call SetupWizard.next(this) here — that would skip lock setup.
                startActivity(Intent(this, CommunityLockActivity::class.java))
                finish()
            }
        }
    }
}
