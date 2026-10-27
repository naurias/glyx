package dev.glyx.app

import android.app.Activity
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class EnableBiometricArgs {
  lateinit var secret: String
  lateinit var vaultId: String
  lateinit var slotId: String
}

@InvokeArg
class UnlockBiometricArgs {
  lateinit var vaultId: String
}

@TauriPlugin
class BiometricPlugin(private val host: Activity) : Plugin(host) {
  companion object {
    private const val PREFS = "glyx_biometric"
    private const val KEY_ALIAS = "glyx-biometric-v1"
    private const val KEY_BLOB = "blob"
    private const val KEY_VAULT_ID = "vault_id"
    private const val KEY_SLOT_ID = "slot_id"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
  }

  private val prefs = host.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
  private val executor = ContextCompat.getMainExecutor(host)

  @Command
  fun status(invoke: Invoke) {
    val result = JSObject()
    result.put("available", canAuthenticate())
    result.put("enabled", prefs.contains(KEY_BLOB) && keyExists())
    prefs.getString(KEY_VAULT_ID, null)?.let { result.put("vault_id", it) }
    prefs.getString(KEY_SLOT_ID, null)?.let { result.put("slot_id", it) }
    invoke.resolve(result)
  }

  @Command
  fun enable(invoke: Invoke) {
    val args = invoke.parseArgs(EnableBiometricArgs::class.java)
    if (!canAuthenticate()) {
      invoke.reject("Biometric authentication is not available")
      return
    }
    try {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
      prompt(invoke, cipher, object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          try {
            val unlocked = result.cryptoObject?.cipher
              ?: throw IllegalStateException("biometric cipher missing")
            val ciphertext = unlocked.doFinal(args.secret.toByteArray(Charsets.UTF_8))
            val blob = Base64.encodeToString(unlocked.iv + ciphertext, Base64.NO_WRAP)
            prefs.edit()
              .putString(KEY_BLOB, blob)
              .putString(KEY_VAULT_ID, args.vaultId)
              .putString(KEY_SLOT_ID, args.slotId)
              .apply()
            val out = JSObject()
            out.put("ok", true)
            invoke.resolve(out)
          } catch (e: Exception) {
            clear()
            invoke.reject(e.message ?: "could not store biometric secret")
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          invoke.reject(errString.toString(), "BIOMETRIC_ERROR")
        }

        override fun onAuthenticationFailed() {}
      })
    } catch (e: Exception) {
      clear()
      invoke.reject(e.message ?: "biometric setup failed")
    }
  }

  @Command
  fun unlock(invoke: Invoke) {
    val args = invoke.parseArgs(UnlockBiometricArgs::class.java)
    if (!prefs.contains(KEY_BLOB) || prefs.getString(KEY_VAULT_ID, null) != args.vaultId) {
      invoke.reject("Biometric unlock is not enabled for this vault")
      return
    }
    val blob = prefs.getString(KEY_BLOB, null)
    if (blob == null) {
      invoke.reject("Biometric unlock is not enabled")
      return
    }
    try {
      val raw = Base64.decode(blob, Base64.NO_WRAP)
      if (raw.size <= 12) throw IllegalStateException("bad biometric record")
      val key = getKey() ?: throw IllegalStateException("biometric key missing")
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(
        Cipher.DECRYPT_MODE,
        key,
        GCMParameterSpec(128, raw.copyOfRange(0, 12))
      )
      prompt(invoke, cipher, object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          try {
            val unlocked = result.cryptoObject?.cipher
              ?: throw IllegalStateException("biometric cipher missing")
            val secret = String(unlocked.doFinal(raw.copyOfRange(12, raw.size)), Charsets.UTF_8)
            val out = JSObject()
            out.put("secret", secret)
            invoke.resolve(out)
          } catch (e: Exception) {
            clear()
            invoke.reject(e.message ?: "biometric unlock failed")
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          invoke.reject(errString.toString(), "BIOMETRIC_ERROR")
        }

        override fun onAuthenticationFailed() {}
      })
    } catch (e: Exception) {
      clear()
      invoke.reject(e.message ?: "biometric unlock failed")
    }
  }

  @Command
  fun disable(invoke: Invoke) {
    clear()
    val out = JSObject()
    out.put("ok", true)
    invoke.resolve(out)
  }

  private fun prompt(
    invoke: Invoke,
    cipher: Cipher,
    callback: BiometricPrompt.AuthenticationCallback
  ) {
    val activity = host as? FragmentActivity
    if (activity == null) {
      invoke.reject("biometric prompt needs a fragment activity")
      return
    }
    val prompt = BiometricPrompt(activity, executor, callback)
    val info = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Unlock glyx")
      .setSubtitle("Use biometrics to unlock your vault")
      .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      .setNegativeButtonText("Cancel")
      .setConfirmationRequired(false)
      .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
  }

  private fun canAuthenticate(): Boolean {
    val manager = BiometricManager.from(host)
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
        BiometricManager.BIOMETRIC_SUCCESS
    } else {
      @Suppress("DEPRECATION")
      manager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS
    }
  }

  private fun keyStore(): KeyStore {
    return KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  }

  private fun keyExists(): Boolean = keyStore().containsAlias(KEY_ALIAS)

  private fun getKey(): SecretKey? {
    val store = keyStore()
    if (!store.containsAlias(KEY_ALIAS)) return null
    return store.getKey(KEY_ALIAS, null) as? SecretKey
  }

  private fun getOrCreateKey(): SecretKey {
    getKey()?.let { return it }
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val builder = KeyGenParameterSpec.Builder(
      KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setUserAuthenticationParameters(
        0,
        KeyProperties.AUTH_BIOMETRIC_STRONG
      )
    }
    generator.init(builder.build())
    return generator.generateKey()
  }

  private fun clear() {
    prefs.edit().clear().apply()
    try {
      keyStore().deleteEntry(KEY_ALIAS)
    } catch (_: Exception) {
    }
  }
}
