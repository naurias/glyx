package dev.glyx.app

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyGetActivity : FragmentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
    val option = providerRequest?.credentialOptions
      ?.filterIsInstance<GetPublicKeyCredentialOption>()
      ?.firstOrNull()
    val itemId = intent.getStringExtra(GlyxCredentialProviderService.EXTRA_ITEM_ID).orEmpty()
    if (providerRequest == null || option == null || itemId.isBlank()) {
      finishCanceled()
      return
    }
    val rpId = runCatching { JSONObject(option.requestJson).optString("rpId") }
      .getOrDefault("")
    prompt(providerRequest, option, itemId, rpId)
  }

  private fun prompt(
    providerRequest: ProviderGetCredentialRequest,
    option: GetPublicKeyCredentialOption,
    itemId: String,
    rpId: String,
  ) {
    val manager = BiometricManager.from(this)
    val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
      BiometricManager.Authenticators.DEVICE_CREDENTIAL
    if (manager.canAuthenticate(allowed) != BiometricManager.BIOMETRIC_SUCCESS) {
      Toast.makeText(this, "Set up a screen lock to use passkeys.", Toast.LENGTH_LONG).show()
      finishCanceled()
      return
    }
    val prompt = BiometricPrompt(
      this,
      ContextCompat.getMainExecutor(this),
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          super.onAuthenticationError(errorCode, errString)
          finishCanceled()
        }

        override fun onAuthenticationFailed() {
          super.onAuthenticationFailed()
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          super.onAuthenticationSucceeded(result)
          sign(providerRequest, option, itemId)
        }
      },
    )
    val info = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Sign in with a passkey")
      .setSubtitle(if (rpId.isBlank()) "Use glyx" else "for $rpId")
      .setAllowedAuthenticators(allowed)
      .build()
    prompt.authenticate(info)
  }

  private fun sign(
    providerRequest: ProviderGetCredentialRequest,
    option: GetPublicKeyCredentialOption,
    itemId: String,
  ) {
    val origin = PasskeyOrigin.forCallingApp(this, providerRequest.callingAppInfo)
    val body = JSONObject()
      .put("origin", origin)
      .put("request", JSONObject(option.requestJson))
      .put("item_id", itemId)
      .put("user_verified", true)
    option.clientDataHash?.let {
      body.put(
        "client_data_hash",
        Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
      )
    }
    Thread {
      val session = GlyxClient.readSession(this)
      val response = session?.let { GlyxClient.request(it, "POST", "/v1/passkeys/get", body) }
      runOnUiThread {
        val credential = response?.optJSONObject("response")
        if (credential == null) {
          Toast.makeText(this, "Could not use the passkey. Unlock glyx and try again.", Toast.LENGTH_LONG).show()
          finishCanceled()
          return@runOnUiThread
        }
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(
          result,
          GetCredentialResponse(PublicKeyCredential(credential.toString())),
        )
        setResult(RESULT_OK, result)
        finish()
      }
    }.start()
  }

  private fun finishCanceled() {
    val result = Intent()
    PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
    setResult(RESULT_CANCELED, result)
    finish()
  }
}
