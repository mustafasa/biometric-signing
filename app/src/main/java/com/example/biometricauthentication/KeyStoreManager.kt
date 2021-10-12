package com.example.biometricauthentication

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.*

/**
 * KeyManager which generates keys pair and sign data within Keystore
 */
object KeyStoreManager {

    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    var isStrongBoxAvailable = false

    /**
     * This method generates ECDSA-256 keypair within KeyStore with Biometric authentication
     * required to sign data.
     * @param keyAlias it is alias name give to generate key and later on to access the key
     * @return PublicKey
     */
    fun generateKeyPairWithBiometric(
        keyAlias: String
    ): PublicKey {

        val keyPairGenerator =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_SHA256
            ) // Require the user to authenticate with a biometric to authorize every use of the key
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(
                isStrongBoxAvailable
            )
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair().public
    }

    /**
     * This method generates ECDSA-256 keypair within KeyStore.
     * @param keyAlias it is alias name give to generate key and later on to access the key
     * @return PublicKey
     */
    fun generateKeyPair(
        keyAlias: String
    ): PublicKey {

        val keyPairGenerator =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE
            )
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setSignaturePaddings()
            .setIsStrongBoxBacked(
                isStrongBoxAvailable
            )
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair().public
    }

    /**
     * Generates signature object.
     * @param keyAlias it is alias name to access the key
     * @return Signature object
     */
    fun initSignature(keyAlias: String): Signature? {
        val keyPair: KeyPair? = checkIfKeyExist(keyAlias)
        if (keyPair != null) {
            val signature =
                Signature.getInstance("SHA256withECDSA")
            try {
                signature.initSign(keyPair.private)
            } catch (e: Exception) {
                Log.e("initSignature", e.toString())
                return null
            }
            return signature
        }
        return null
    }

    /**
     * This method signs the data with provided parameters
     * @param Signature object
     * [70byte,size,something.10bytes]
     * @param data byteArray of data to be signed.
     */
    fun signData(
        signature: Signature?,
        data: ByteArray
    ): ByteArray {
        try {
            signature?.update(data)
            return signature?.sign()!!
        } catch (e: Exception) {
            Log.d("KeyStoreManager SignatureException ", e.toString())
            return ByteArray(10)
        }
    }

    /**
     *  To verify signature is valid.
     */
    fun verifySign(
        keyAlias: String,
        data: ByteArray,
        sig: ByteArray
    ): Boolean {
        val keypair: KeyPair? = checkIfKeyExist(keyAlias) ?: return false
        val referenceSignature = Signature.getInstance("SHA256withECDSA")
        referenceSignature.initVerify(keypair?.public)
        referenceSignature.update(data)
        val verifies = referenceSignature.verify(sig)
        Log.d("KeyStoreManager verifySign ", verifies.toString())
        return verifies
    }

    /**
     * Delete the keypair if exists.
     */
    fun deleteKeyPair(keyAlias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
            return true
        }
        return false
    }

    private fun checkIfKeyExist(keyAlias: String): KeyPair? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (keyStore.containsAlias(keyAlias)) {
            // Get public key
            val publicKey = keyStore.getCertificate(keyAlias).publicKey

            Log.d("KeyStoreManager Certificate ", keyStore.getCertificate(keyAlias).toString())
            keyStore.getCertificate(keyAlias)

            // Get private key
            val privateKey =
                keyStore.getKey(keyAlias, null) as PrivateKey
            return KeyPair(publicKey, privateKey)
        }
        return null
    }
}