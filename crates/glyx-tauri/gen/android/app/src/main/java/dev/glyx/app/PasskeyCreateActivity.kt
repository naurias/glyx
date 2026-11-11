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
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyCreateActivity : FragmentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val providerRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
    val calling = providerRequest?.callingRequest as? CreatePublicKeyCredentialRequest
    if (providerRequest == null || calling == null) {
      finishCanceled()
      return
    }
    val rpName = runCatching {
      JSONObject(calling.requestJson).optJSONObject("rp")?.optString("name").orEmpty()
    }.getOrDefault("")
    prompt(providerRequest, calling, rpName)
  }

  private fun prompt(
    providerRequest: ProviderCreateCredentialRequest,
    calling: CreatePublicKeyCredentialRequest,
    rpName: String,
  ) {
    val manager = BiometricManager.from(this)
    val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
      BiometricManager.Authenticators.DEVICE_CREDENTIAL
    if (manager.canAuthenticate(allowed) != BiometricManager.BIOMETRIC_SUCCESS) {
      Toast.makeText(this, "Set up a screen lock to create passkeys.", Toast.LENGTH_LONG).show()
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
          create(providerRequest, calling)
        }
      },
    )
    val info = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Create a passkey")
      .setSubtitle(if (rpName.isBlank()) "Save it in glyx" else "for $rpName")
      .setAllowedAuthenticators(allowed)
      .build()
    prompt.authenticate(info)
  }

  private fun create(
    providerRequest: androidx.credentials.provider.ProviderCreateCredentialRequest,
    calling: CreatePublicKeyCredentialRequest,
  ) {
    val origin = PasskeyOrigin.forCallingApp(this, providerRequest.callingAppInfo)
    val body = JSONObject()
      .put("origin", origin)
      .put("request", JSONObject(calling.requestJson))
      .put("user_verified", true)
    calling.clientDataHash?.let {
      body.put(
        "client_data_hash",
        Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING),
      )
    }
    Thread {
      val session = GlyxClient.readSession(this)
      val response = session?.let { GlyxClient.request(it, "POST", "/v1/passkeys/create", body) }
      runOnUiThread {
        val credential = response?.optJSONObject("response")
        if (credential == null) {
          Toast.makeText(this, "Could not create the passkey. Unlock glyx and try again.", Toast.LENGTH_LONG).show()
          finishCanceled()
          return@runOnUiThread
        }
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(
          result,
          CreatePublicKeyCredentialResponse(credential.toString()),
        )
        setResult(RESULT_OK, result)
        finish()
      }
    }.start()
  }

  private fun finishCanceled() {
    val result = Intent()
    PendingIntentHandler.setCreateCredentialException(
      result,
      CreateCredentialCancellationException(),
    )
    setResult(RESULT_CANCELED, result)
    finish()
  }
}
