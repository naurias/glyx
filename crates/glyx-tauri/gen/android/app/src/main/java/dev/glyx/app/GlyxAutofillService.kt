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

class GlyxAutofillService : AutofillService() {
  companion object {
    private val OTP_PATTERN =
      Regex("otp|totp|2fa|one.?time|verification|authenticator|security.?code")
  }

  private data class Fields(
    var username: AutofillId? = null,
    var password: AutofillId? = null,
    var otp: AutofillId? = null,
    val otpDigits: MutableMap<Int, AutofillId> = mutableMapOf(),
    var webDomain: String? = null,
    var usernameValue: String = "",
    var passwordValue: String = "",
  )

  private data class Login(
    val id: String,
    val name: String,
    val username: String,
    val password: String,
    val totpItemId: String?,
  )

  private data class TotpItem(
    val id: String,
    val name: String,
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
    if (fields.username == null &&
      fields.password == null &&
      fields.otp == null &&
      fields.otpDigits.isEmpty()
    ) {
      callback.onSuccess(null)
      return
    }
    val targetPackage = structure.activityComponent?.packageName ?: return callback.onSuccess(null)
    if (targetPackage == packageName) {
      callback.onSuccess(null)
      return
    }
    val session = GlyxClient.readSession(this)
    if (session == null) {
      callback.onSuccess(unlockResponse(fields))
      return
    }
    Thread {
      val domain = fields.webDomain
      val logins = queryLogins(session, domain, targetPackage)
      val totps = if (domain != null) {
        queryTotpItems(session, domain)
      } else {
        emptyList()
      }
      val response = when {
        logins == null -> unlockResponse(fields)
        else -> buildResponse(session, fields, logins, totps)
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
    val session = GlyxClient.readSession(this)
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
    val passwordField = isPasswordField(node, hints, inputType)
    val usernameField = !passwordField && isUsernameField(node, hints, inputType)
    val otpField = isOtpField(node, hints, inputType)
    if (passwordField && fields.password == null) {
      fields.password = node.autofillId
    }
    if (!passwordField && usernameField && fields.username == null) {
      fields.username = node.autofillId
    }
    if (otpField && !passwordField) {
      val positions = hints.mapNotNull { hint ->
        if (hint.startsWith("smsOTPCode")) {
          val suffix = hint.removePrefix("smsOTPCode")
          if (suffix.isEmpty()) 0 else suffix.toIntOrNull()
        } else {
          null
        }
      }
      val id = node.autofillId
      if (id != null) {
        if (positions.any { it > 0 }) {
          for (position in positions) {
            if (position > 0) fields.otpDigits.putIfAbsent(position, id)
          }
        } else if (fields.otp == null) {
          fields.otp = id
        }
      }
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
    val passwordField = isPasswordField(node, hints, inputType)
    val usernameField = !passwordField && isUsernameField(node, hints, inputType)
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

  private fun fieldText(node: android.app.assist.AssistStructure.ViewNode): String =
    listOfNotNull(node.idEntry, node.hint?.toString()).joinToString(" ").lowercase()

  private fun isPasswordField(
    node: android.app.assist.AssistStructure.ViewNode,
    hints: Array<out String>,
    inputType: Int,
  ): Boolean {
    if (hints.any { it == View.AUTOFILL_HINT_PASSWORD || it == "newPassword" }) return true
    if ((inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) ==
      InputType.TYPE_TEXT_VARIATION_PASSWORD
    ) {
      return true
    }
    if ((inputType and InputType.TYPE_NUMBER_VARIATION_PASSWORD) ==
      InputType.TYPE_NUMBER_VARIATION_PASSWORD
    ) {
      return true
    }
    return node.autofillId != null && fieldText(node).contains("pass")
  }

  private fun isUsernameField(
    node: android.app.assist.AssistStructure.ViewNode,
    hints: Array<out String>,
    inputType: Int,
  ): Boolean {
    if (hints.any {
        it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS
      }
    ) {
      return true
    }
    if ((inputType and InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS) ==
      InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
    ) {
      return true
    }
    if ((inputType and InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) ==
      InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    ) {
      return true
    }
    if (node.autofillId == null) return false
    val text = fieldText(node)
    return listOf("user", "email", "login", "account", "identifier").any { text.contains(it) }
  }

  private fun isOtpField(
    node: android.app.assist.AssistStructure.ViewNode,
    hints: Array<out String>,
    inputType: Int,
  ): Boolean {
    if (hints.any {
        it == "smsOTPCode" ||
          it == "2faAppOTPCode" ||
          it.startsWith("smsOTPCode")
      }
    ) {
      return true
    }
    val numeric = (inputType and InputType.TYPE_CLASS_NUMBER) == InputType.TYPE_CLASS_NUMBER
    if (!numeric) return false
    return OTP_PATTERN.containsMatchIn(fieldText(node))
  }

  private fun buildResponse(
    session: GlyxSession,
    fields: Fields,
    logins: List<Login>,
    totps: List<TotpItem>,
  ): FillResponse? {
    val wantsOtp = fields.otp != null || fields.otpDigits.isNotEmpty()
    val response = FillResponse.Builder()
    var added = 0
    for (login in logins) {
      val code = if (wantsOtp && login.totpItemId != null) {
        fetchCode(session, login.totpItemId)
      } else {
        null
      }
      val dataset = buildDataset(
        fields = fields,
        label = login.name,
        detail = login.username.ifEmpty { "glyx" },
        username = login.username,
        password = login.password,
        code = code,
      )
      if (dataset != null) {
        response.addDataset(dataset)
        added++
      }
    }
    if (wantsOtp) {
      for (totp in totps) {
        if (logins.any { it.totpItemId == totp.id }) continue
        val code = fetchCode(session, totp.id) ?: continue
        val dataset = buildDataset(
          fields = fields,
          label = totp.name,
          detail = "TOTP",
          username = "",
          password = "",
          code = code,
        )
        if (dataset != null) {
          response.addDataset(dataset)
          added++
        }
      }
    }
    if (added == 0) return saveOnlyResponse(fields)
    saveInfo(fields)?.let { response.setSaveInfo(it) }
    return runCatching { response.build() }.getOrNull()
  }

  private fun buildDataset(
    fields: Fields,
    label: String,
    detail: String,
    username: String,
    password: String,
    code: String?,
  ): Dataset? {
    val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
      setTextViewText(R.id.autofill_label, label)
      setTextViewText(R.id.autofill_detail, detail)
    }
    val dataset = Dataset.Builder(presentation)
    var hasValue = false
    fields.username?.let { id ->
      if (username.isNotEmpty()) {
        dataset.setValue(id, AutofillValue.forText(username))
        hasValue = true
      }
    }
    fields.password?.let { id ->
      if (password.isNotEmpty()) {
        dataset.setValue(id, AutofillValue.forText(password))
        hasValue = true
      }
    }
    if (code != null) {
      fields.otp?.let { id ->
        dataset.setValue(id, AutofillValue.forText(code))
        hasValue = true
      }
      for ((position, id) in fields.otpDigits) {
        val digit = code.getOrNull(position - 1)?.toString()
        if (digit != null) {
          dataset.setValue(id, AutofillValue.forText(digit))
          hasValue = true
        }
      }
    }
    return if (hasValue) dataset.build() else null
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
    if (fields.username == null &&
      fields.password == null &&
      fields.otp == null &&
      fields.otpDigits.isEmpty()
    ) {
      return null
    }
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

  private fun queryLogins(
    session: GlyxSession,
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
    val response = GlyxClient.request(session, "POST", "/v1/logins/list", body) ?: return null
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
          totpItemId = row.optString("totp_item_id").ifEmpty { null },
        )
      )
      if (out.size >= 10) break
    }
    return out
  }

  private fun queryTotpItems(session: GlyxSession, webDomain: String): List<TotpItem> {
    val body = JSONObject()
      .put("origin", "https://$webDomain")
      .put("limit", 10)
    val response = GlyxClient.request(session, "POST", "/v1/totp/list", body) ?: return emptyList()
    val matches = response.optJSONArray("matches") ?: return emptyList()
    val out = ArrayList<TotpItem>()
    for (index in 0 until matches.length()) {
      val row = matches.optJSONObject(index) ?: continue
      val id = row.optString("id")
      if (id.isBlank()) continue
      out.add(TotpItem(id, row.optString("name", "TOTP")))
      if (out.size >= 10) break
    }
    return out
  }

  private fun fetchCode(session: GlyxSession, itemId: String): String? {
    val response = GlyxClient.request(session, "GET", "/v1/items/$itemId/totp") ?: return null
    return response.optString("code").ifEmpty { null }
  }

  private fun saveLogin(session: GlyxSession, fields: Fields, targetPackage: String): Boolean {
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
    val match = GlyxClient.request(session, "POST", "/v1/logins/match", matchBody)
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
      return GlyxClient.request(session, "PATCH", "/v1/items/$id", body) != null
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
    return GlyxClient.request(session, "POST", "/v1/items", body) != null
  }

  private fun appLabel(packageName: String): String? = runCatching {
    val info = packageManager.getApplicationInfo(packageName, 0)
    packageManager.getApplicationLabel(info).toString()
  }.getOrNull()
}
