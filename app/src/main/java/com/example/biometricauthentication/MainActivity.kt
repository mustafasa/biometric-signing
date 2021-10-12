package com.example.biometricauthentication

import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import com.example.biometricauthentication.KeyStoreManager.deleteKeyPair
import com.example.biometricauthentication.KeyStoreManager.generateKeyPairWithBiometric
import com.example.biometricauthentication.KeyStoreManager.initSignature
import com.example.biometricauthentication.KeyStoreManager.isStrongBoxAvailable
import com.example.biometricauthentication.KeyStoreManager.signData
import com.example.biometricauthentication.KeyStoreManager.verifySign
import java.security.Signature
import java.security.SignatureException

class MainActivity : AppCompatActivity() {
    private val DATA = "Hello".toByteArray()
    private val KEY_ALIAS = "RemoteKey"
    private val TAG = "RemoteMainActivity"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        isStrongBoxAvailable =
                this.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        initStrongerAuthUi()
    }

    private fun initStrongerAuthUi() {

        (findViewById(R.id.signBioButton) as Button).setOnClickListener {
            val signature = initSignature(KEY_ALIAS)
            (findViewById(R.id.textView) as TextView).setText("Signing Data")
            Log.d(
                    TAG, "Signing Data"
            )
            if (signature != null) {
                showBiometricPrompt(signature)
            } else {
                Log.d(
                        TAG, "Key is not generated or key was revoked due bio change"
                )
                (findViewById(R.id.textView) as TextView).setText("Key is not generated or key was revoked due bio change")
            }
        }

        (findViewById(R.id.generateKeyPair) as Button).setOnClickListener {
            Log.d(
                    TAG, "Generating Key"
            )
            (findViewById(R.id.textView) as TextView).setText("Generating Key")
            generateKeyPairWithBiometric(KEY_ALIAS)
            Log.d(
                    TAG, "Key generated"
            )
            (findViewById(R.id.textView) as TextView).setText("Key generated")

        }

        (findViewById(R.id.deleteKey) as Button).setOnClickListener {
            Log.d(
                    TAG, "Deleting Key"
            )
            (findViewById(R.id.textView) as TextView).setText("Deleting Key")
            if (deleteKeyPair(KEY_ALIAS)) {
                Log.d(
                        TAG, "Key deleted"
                )
                (findViewById(R.id.textView) as TextView).setText("Key deleted")
            } else {
                Log.d(
                        TAG, "Key not deleted or not found"
                )
                (findViewById(R.id.textView) as TextView).setText("Key not deleted or not found")
            }
        }
    }

    private fun showBiometricPrompt(signature: Signature?) {
        val mBiometricPrompt =
                BiometricPrompt(
                        this,
                        getAuthenticationCallback()
                )
        // Set prompt info
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setDescription("Remote Bolus Feature enabler")
                .setTitle("Authenticate your biometric")
//            .setAllowedAuthenticators(BIOMETRIC_WEAK) // this can't be set on CryptoObject
                .setConfirmationRequired(false)
                .setNegativeButtonText("Cancel")
                .build()
        // Show biometric prompt
        if (signature != null) {
            Log.i("showBiometricPrompt", "Show biometric prompt")
            mBiometricPrompt.authenticate(
                    promptInfo,
                    BiometricPrompt.CryptoObject(signature)
            )
        }
    }

    private fun getAuthenticationCallback(): BiometricPrompt.AuthenticationCallback {
        // Callback for biometric authentication result
        return object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.e(
                        TAG,
                        "onAuthenticationError Error code: " + errorCode + "error String: " + errString
                )
                super.onAuthenticationError(errorCode, errString)
                Toast.makeText(applicationContext, "Biometric not available", Toast.LENGTH_SHORT)
                        .show()
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(
                        TAG,
                        "onAuthenticationSucceeded"
                )
                if (result.cryptoObject != null &&
                        result.cryptoObject!!.signature != null
                ) {
                    try {
                        val signature =
                                result.cryptoObject!!.signature
                        if (verifySign(KEY_ALIAS, DATA, signData(signature, DATA))) {
                            (findViewById(R.id.textView) as TextView).setText("Signature verified")
                            Log.d(
                                    TAG, "Signature verified"
                            )
                        } else {
                            Log.d(
                                    TAG, "Signature verification failed"
                            )
                            (findViewById(R.id.textView) as TextView).setText("Signature verification failed")
                        }
                    } catch (e: SignatureException) {
                        throw RuntimeException()
                    }
                } else {
                    // Error
                    Toast.makeText(applicationContext, "Something wrong", Toast.LENGTH_SHORT)
                            .show()
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Error
                Log.d(
                        TAG, "onAuthenticationFailed"
                )
                Toast.makeText(
                        applicationContext,
                        "Biometric can't be authenticated",
                        Toast.LENGTH_SHORT
                )
                        .show()
            }
        }
    }
}