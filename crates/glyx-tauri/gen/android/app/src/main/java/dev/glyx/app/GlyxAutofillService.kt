package dev.glyx.app

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

class GlyxAutofillService : AutofillService() {
  private data class Fields(
    var username: AutofillId? = null,
    var password: AutofillId? = null,
    var webDomain: String? = null,
    var usernameValue: String = "",
    var passwordValue: String = "",
  )

  private data class Login(
    val id: String,
    val name: String,
    val username: String,
    val password: String,
  )

  private data class Session(
    val url: String,
    val token: String,
  )

  override fun onFillRequest(
    request: FillRequest,
    cancellationSignal: CancellationSignal,
    callback: FillCallback,
  ) {
    val structure = request.fillContexts.lastOrNull()?.structure
    if (structure == null) {
      callback.onSuccess(null)
      return
    }
    val fields = Fields()
    if (structure.windowNodeCount > 0) {
      walk(structure.getWindowNodeAt(0).rootViewNode, fields)
    }
    if (fields.username == null && fields.password == null) {
      callback.onSuccess(null)
      return
    }
    val targetPackage = structure.activityComponent?.packageName ?: return callback.onSuccess(null)
    if (targetPackage == packageName) {
      callback.onSuccess(null)
      return
    }
    val session = readSession()
    if (session == null) {
      callback.onSuccess(unlockResponse(fields))
      return
    }
    Thread {
      val matches = queryLogins(session, fields.webDomain, targetPackage)
      val response = when {
        matches == null -> unlockResponse(fields)
        matches.isEmpty() -> saveOnlyResponse(fields)
        else -> buildResponse(fields, matches)
      }
      callback.onSuccess(response)
    }.start()
  }

  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    val structure = request.fillContexts.lastOrNull()?.structure
    if (structure == null) {
      callback.onSuccess()
      return
    }
    val fields = Fields()
    if (structure.windowNodeCount > 0) {
      walkValues(structure.getWindowNodeAt(0).rootViewNode, fields)
    }
    val targetPackage = structure.activityComponent?.packageName ?: return callback.onSuccess()
    if (targetPackage == packageName) {
      callback.onSuccess()
      return
    }
    if (fields.passwordValue.isBlank()) {
      callback.onSuccess()
      return
    }
    val session = readSession()
    if (session == null) {
      callback.onFailure("glyx is locked; unlock and try again")
      return
    }
    Thread {
      if (saveLogin(session, fields, targetPackage)) {
        callback.onSuccess()
      } else {
        callback.onFailure("could not save to glyx")
      }
    }.start()
  }

  private fun walk(node: android.app.assist.AssistStructure.ViewNode?, fields: Fields) {
    if (node == null) return
    if (node.visibility != View.VISIBLE || !node.isEnabled) return
    node.webDomain?.let { fields.webDomain = it }
    val hints = node.autofillHints.orEmpty()
    val inputType = node.inputType
    val passwordField =
      hints.any { it == View.AUTOFILL_HINT_PASSWORD || it == "newPassword" } ||
        (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) ==
          InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        (inputType and InputType.TYPE_NUMBER_VARIATION_PASSWORD) ==
          InputType.TYPE_NUMBER_VARIATION_PASSWORD
    val usernameField =
      hints.any {
        it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS
      } ||
        (inputType and InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS) ==
          InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
        (inputType and InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) ==
          InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    if (passwordField && fields.password == null) {
      fields.password = node.autofillId
    }
    if (!passwordField && usernameField && fields.username == null) {
      fields.username = node.autofillId
    }
    for (index in 0 until node.childCount) {
      walk(node.getChildAt(index), fields)
    }
  }

  private fun walkValues(node: android.app.assist.AssistStructure.ViewNode?, fields: Fields) {
    if (node == null) return
    if (node.visibility != View.VISIBLE || !node.isEnabled) return
    node.webDomain?.let { fields.webDomain = it }
    val hints = node.autofillHints.orEmpty()
    val inputType = node.inputType
    val passwordField =
      hints.any { it == View.AUTOFILL_HINT_PASSWORD || it == "newPassword" } ||
        (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) ==
          InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        (inputType and InputType.TYPE_NUMBER_VARIATION_PASSWORD) ==
          InputType.TYPE_NUMBER_VARIATION_PASSWORD
    val usernameField =
      hints.any {
        it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS
      } ||
        (inputType and InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS) ==
          InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
        (inputType and InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) ==
          InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    if (passwordField && fields.password == null) {
      fields.password = node.autofillId
      fields.passwordValue = node.autofillValue?.textValue?.toString().orEmpty()
    }
    if (!passwordField && usernameField && fields.username == null) {
      fields.username = node.autofillId
      fields.usernameValue = node.autofillValue?.textValue?.toString().orEmpty()
    }
    for (index in 0 until node.childCount) {
      walkValues(node.getChildAt(index), fields)
    }
  }

  private fun buildResponse(fields: Fields, items: List<Login>): FillResponse? {
    val response = FillResponse.Builder()
    var added = 0
    for (item in items) {
      val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
        setTextViewText(R.id.autofill_label, item.name)
        setTextViewText(R.id.autofill_detail, item.username.ifEmpty { "glyx" })
      }
      val dataset = Dataset.Builder(presentation)
      var hasValue = false
      fields.username?.let { id ->
        if (item.username.isNotEmpty()) {
          dataset.setValue(id, AutofillValue.forText(item.username))
          hasValue = true
        }
      }
      fields.password?.let { id ->
        if (item.password.isNotEmpty()) {
          dataset.setValue(id, AutofillValue.forText(item.password))
          hasValue = true
        }
      }
      if (hasValue) {
        response.addDataset(dataset.build())
        added++
      }
    }
    if (added == 0) return saveOnlyResponse(fields)
    saveInfo(fields)?.let { response.setSaveInfo(it) }
    return runCatching { response.build() }.getOrNull()
  }

  private fun saveOnlyResponse(fields: Fields): FillResponse? {
    val info = saveInfo(fields) ?: return null
    return runCatching { FillResponse.Builder().setSaveInfo(info).build() }.getOrNull()
  }

  private fun saveInfo(fields: Fields): SaveInfo? {
    val ids = listOfNotNull(fields.username, fields.password)
    if (ids.isEmpty()) return null
    val type = when {
      fields.username != null && fields.password != null ->
        SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD
      fields.username != null -> SaveInfo.SAVE_DATA_TYPE_USERNAME
      else -> SaveInfo.SAVE_DATA_TYPE_PASSWORD
    }
    return runCatching { SaveInfo.Builder(type, ids.toTypedArray()).build() }.getOrNull()
  }

  private fun unlockResponse(fields: Fields): FillResponse? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
    if (fields.username == null && fields.password == null) return null
    val intent = Intent(this, MainActivity::class.java)
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    val pending = PendingIntent.getActivity(
      this,
      0,
      intent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
    val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
      setTextViewText(R.id.autofill_label, "Unlock glyx")
      setTextViewText(R.id.autofill_detail, "Unlock the vault to fill")
    }
    return runCatching {
      FillResponse.Builder()
        .addDataset(Dataset.Builder(presentation).setAuthentication(pending.intentSender).build())
        .build()
    }.getOrNull()
  }

  private fun readSession(): Session? {
    val file = File(dataDir, "glyx-mobile.json")
    if (!file.isFile) return null
    return runCatching {
      val json = JSONObject(file.readText())
      val url = json.optString("url")
      val token = json.optString("token")
      if (url.isBlank() || token.isBlank()) null else Session(url, token)
    }.getOrNull()
  }

  private fun queryLogins(
    session: Session,
    webDomain: String?,
    targetPackage: String,
  ): List<Login>? {
    val body = JSONObject().apply {
      if (webDomain != null) {
        put("origin", "https://$webDomain")
      } else {
        put("package", targetPackage)
      }
      put("limit", 10)
    }
    val response = requestJson(session, "POST", "/v1/logins/list", body) ?: return null
    val matches = response.optJSONArray("matches") ?: return emptyList()
    val out = ArrayList<Login>()
    for (index in 0 until matches.length()) {
      val row = matches.optJSONObject(index) ?: continue
      val id = row.optString("id")
      if (id.isBlank()) continue
      out.add(
        Login(
          id = id,
          name = row.optString("name", "glyx"),
          username = row.optString("username"),
          password = row.optString("password"),
        )
      )
      if (out.size >= 10) break
    }
    return out
  }

  private fun saveLogin(session: Session, fields: Fields, targetPackage: String): Boolean {
    val host = fields.webDomain?.trim()?.lowercase()
    val packageName = if (host == null) targetPackage else ""
    val url = if (host != null) "https://$host" else ""
    val username = fields.usernameValue.trim()
    val password = fields.passwordValue
    if (username.isEmpty() && password.isEmpty()) return true
    val matchBody = JSONObject().apply {
      if (host != null) put("origin", url)
      if (packageName.isNotEmpty()) put("package", packageName)
      put("username", username)
    }
    val match = requestJson(session, "POST", "/v1/logins/match", matchBody)
      ?.optJSONObject("match")
    if (match != null) {
      val id = match.optString("id")
      if (id.isBlank()) return false
      if (match.optString("password") == password) return true
      val body = JSONObject().put(
        "fields",
        JSONObject().apply {
          put("username", username)
          put("password", password)
          if (url.isNotEmpty()) put("url", url)
          if (packageName.isNotEmpty()) put("package", packageName)
        },
      )
      return requestJson(session, "PATCH", "/v1/items/$id", body) != null
    }
    if (username.isEmpty()) return true
    val name = host ?: appLabel(targetPackage) ?: targetPackage
    val body = JSONObject()
      .put("type", "login")
      .put("name", name)
      .put(
        "fields",
        JSONObject().apply {
          put("username", username)
          put("password", password)
          if (url.isNotEmpty()) put("url", url)
          if (packageName.isNotEmpty()) put("package", packageName)
        },
      )
    return requestJson(session, "POST", "/v1/items", body) != null
  }

  private fun appLabel(packageName: String): String? = runCatching {
    val info = packageManager.getApplicationInfo(packageName, 0)
    packageManager.getApplicationLabel(info).toString()
  }.getOrNull()

  private fun requestJson(
    session: Session,
    method: String,
    path: String,
    body: JSONObject? = null,
  ): JSONObject? {
    var connection: HttpURLConnection? = null
    return try {
      val conn = (URL(session.url + path).openConnection() as HttpURLConnection).apply {
        requestMethod = method
        setRequestProperty("Authorization", "Bearer ${session.token}")
        setRequestProperty("Accept", "application/json")
        connectTimeout = 1500
        readTimeout = 2500
        if (body != null) {
          doOutput = true
          setRequestProperty("Content-Type", "application/json")
        }
      }
      connection = conn
      if (body != null) {
        conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
      }
      if (conn.responseCode !in 200..299) {
        null
      } else {
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        if (text.isBlank()) JSONObject() else JSONObject(text)
      }
    } catch (_: Exception) {
      null
    } finally {
      connection?.disconnect()
    }
  }
}
