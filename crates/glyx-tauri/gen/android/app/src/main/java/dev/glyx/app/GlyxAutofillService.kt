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
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class GlyxAutofillService : AutofillService() {
  private data class Fields(
    var username: AutofillId? = null,
    var password: AutofillId? = null,
    var webDomain: String? = null,
  )

  private data class Item(
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
      val items = queryItems(session, fields.webDomain, targetPackage)
      callback.onSuccess(
        when {
          items == null -> unlockResponse(fields)
          items.isEmpty() -> null
          else -> buildResponse(fields, items)
        }
      )
    }.start()
  }

  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    callback.onSuccess()
  }

  private fun walk(node: android.app.assist.AssistStructure.ViewNode?, fields: Fields) {
    if (node == null) return
    node.webDomain?.let { fields.webDomain = it }
    val hints = node.autofillHints.orEmpty()
    if (hints.any {
        it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS
      }
    ) {
      fields.username = node.autofillId
    }
    if (hints.any { it == View.AUTOFILL_HINT_PASSWORD }) {
      fields.password = node.autofillId
    }
    val inputType = node.inputType
    if (fields.password == null &&
      (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        inputType and InputType.TYPE_NUMBER_VARIATION_PASSWORD == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
    ) {
      fields.password = node.autofillId
    }
    if (fields.username == null &&
      (inputType and InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
        inputType and InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)
    ) {
      fields.username = node.autofillId
    }
    for (index in 0 until node.childCount) {
      walk(node.getChildAt(index), fields)
    }
  }

  private fun buildResponse(fields: Fields, items: List<Item>): FillResponse? {
    val response = FillResponse.Builder()
    for (item in items) {
      val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
        setTextViewText(R.id.autofill_label, item.name)
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
      if (hasValue) response.addDataset(dataset.build())
    }
    return runCatching { response.build() }.getOrNull()
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

  private fun queryItems(
    session: Session,
    webDomain: String?,
    targetPackage: String,
  ): List<Item>? {
    val query = URLEncoder.encode(webDomain ?: targetPackage, "UTF-8")
    val list = getJson(session, "/v1/items?type=login&limit=20&q=$query") as? JSONArray ?: return null
    val out = ArrayList<Item>()
    for (index in 0 until list.length()) {
      val row = list.optJSONObject(index) ?: continue
      val id = row.optString("id")
      if (id.isBlank()) continue
      val detail = getJson(session, "/v1/items/$id?reveal=true") as? JSONObject ?: continue
      val fields = detail.optJSONObject("fields") ?: continue
      val username = fields.optString("username")
      val password = fields.optString("password")
      if (username.isBlank() && password.isBlank()) continue
      out.add(Item(detail.optString("name", "glyx"), username, password))
      if (out.size >= 10) break
    }
    return out
  }

  private fun getJson(session: Session, path: String): Any? {
    var connection: HttpURLConnection? = null
    return try {
      connection = (URL(session.url + path).openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        setRequestProperty("Authorization", "Bearer ${session.token}")
        setRequestProperty("Accept", "application/json")
        connectTimeout = 1500
        readTimeout = 2500
      }
      if (connection.responseCode != HttpURLConnection.HTTP_OK) return null
      val body = connection.inputStream.bufferedReader().use { it.readText() }
      if (body.trimStart().startsWith("[")) JSONArray(body) else JSONObject(body)
    } catch (_: Exception) {
      null
    } finally {
      connection?.disconnect()
    }
  }
}
