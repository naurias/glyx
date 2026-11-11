package dev.glyx.app

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.json.JSONArray
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class GlyxCredentialProviderService : CredentialProviderService() {
  companion object {
    const val ACTION_CREATE = "dev.glyx.app.PASSKEY_CREATE"
    const val ACTION_GET = "dev.glyx.app.PASSKEY_GET"
    const val EXTRA_ITEM_ID = "dev.glyx.app.ITEM_ID"
    const val EXTRA_CREDENTIAL_ID = "dev.glyx.app.CREDENTIAL_ID"
  }

  override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
  ) {
    if (request !is BeginCreatePublicKeyCredentialRequest) {
      callback.onResult(BeginCreateCredentialResponse(emptyList()))
      return
    }
    val rpName = runCatching {
      JSONObject(request.requestJson).optJSONObject("rp")?.optString("name").orEmpty()
    }.getOrDefault("")
    Thread {
      val response = runCatching {
        if (!GlyxClient.unlocked(this)) {
          BeginCreateCredentialResponse(emptyList())
        } else {
          val pending = PendingIntent.getActivity(
            this,
            1001,
            Intent(this, PasskeyCreateActivity::class.java).setAction(ACTION_CREATE),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
          )
          val entry = CreateEntry(
            accountName = if (rpName.isBlank()) "glyx" else rpName,
            pendingIntent = pending,
            description = getString(R.string.credential_provider_label),
            icon = Icon.createWithResource(this, R.mipmap.ic_launcher),
          )
          BeginCreateCredentialResponse(listOf(entry))
        }
      }.getOrElse { BeginCreateCredentialResponse(emptyList()) }
      callback.onResult(response)
    }.start()
  }

  override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    Thread {
      val response = runCatching {
        val session = GlyxClient.readSession(this)
        if (session == null || !GlyxClient.unlocked(this)) {
          BeginGetCredentialResponse(authenticationActions = listOf(unlockAction()))
        } else {
          BeginGetCredentialResponse(lookupEntries(session, request))
        }
      }.getOrElse {
        BeginGetCredentialResponse(authenticationActions = listOf(unlockAction()))
      }
      callback.onResult(response)
    }.start()
  }

  private fun lookupEntries(
    session: GlyxSession,
    request: BeginGetCredentialRequest,
  ): List<CredentialEntry> {
    val entries = mutableListOf<CredentialEntry>()
    val icon = Icon.createWithResource(this, R.mipmap.ic_launcher)
    val origin = PasskeyOrigin.forCallingApp(this, request.callingAppInfo)
    for (option in request.beginGetCredentialOptions) {
      if (option !is BeginGetPublicKeyCredentialOption) continue
      val requestJson = runCatching { JSONObject(option.requestJson) }.getOrNull() ?: continue
      val rpId = requestJson.optString("rpId")
      if (rpId.isBlank()) continue
      val allow = requestJson.optJSONArray("allowCredentials") ?: JSONArray()
      val ids = JSONArray()
      for (index in 0 until allow.length()) {
        val id = allow.optJSONObject(index)?.optString("id").orEmpty()
        if (id.isNotEmpty()) ids.put(id)
      }
      val body = JSONObject()
        .put("origin", origin)
        .put("rp_id", rpId)
        .put("allow_credentials", ids)
      val raw = GlyxClient.requestRaw(session, "POST", "/v1/passkeys/lookup", body) ?: continue
      val matches = runCatching { JSONArray(raw) }.getOrNull() ?: continue
      for (index in 0 until matches.length()) {
        val row = matches.optJSONObject(index) ?: continue
        val itemId = row.optString("item_id")
        if (itemId.isBlank()) continue
        val pending = PendingIntent.getActivity(
          this,
          2000 + (itemId.hashCode() and 0xFFFF),
          Intent(this, PasskeyGetActivity::class.java)
            .setAction(ACTION_GET)
            .putExtra(EXTRA_ITEM_ID, itemId)
            .putExtra(EXTRA_CREDENTIAL_ID, row.optString("credential_id")),
          PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val username = row.optString("user_name").ifEmpty { row.optString("name") }
        val display = row.optString("display_name").ifEmpty { username }
        entries.add(
          PublicKeyCredentialEntry(
            context = this,
            username = username,
            pendingIntent = pending,
            beginGetPublicKeyCredentialOption = option,
            displayName = display,
            icon = icon,
          )
        )
      }
    }
    return entries
  }

  override fun onClearCredentialStateRequest(
    request: androidx.credentials.provider.ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    callback.onResult(null)
  }

  private fun unlockAction(): AuthenticationAction {
    val intent = Intent(this, MainActivity::class.java)
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    val pending = PendingIntent.getActivity(
      this,
      3001,
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    return AuthenticationAction(getString(R.string.unlock_glyx), pending)
  }
}
