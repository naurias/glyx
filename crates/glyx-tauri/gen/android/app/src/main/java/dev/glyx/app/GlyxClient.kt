package dev.glyx.app

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class GlyxSession(val url: String, val token: String)

object GlyxClient {
  fun readSession(context: Context): GlyxSession? {
    val file = File(context.dataDir, "glyx-mobile.json")
    if (!file.isFile) return null
    return runCatching {
      val json = JSONObject(file.readText())
      val url = json.optString("url")
      val token = json.optString("token")
      if (url.isBlank() || token.isBlank()) null else GlyxSession(url, token)
    }.getOrNull()
  }

  fun request(
    session: GlyxSession,
    method: String,
    path: String,
    body: JSONObject? = null,
  ): JSONObject? {
    val text = requestRaw(session, method, path, body) ?: return null
    return if (text.isBlank()) JSONObject() else runCatching { JSONObject(text) }.getOrNull()
  }

  fun requestRaw(
    session: GlyxSession,
    method: String,
    path: String,
    body: JSONObject? = null,
  ): String? {
    var connection: HttpURLConnection? = null
    return try {
      val conn = (URL(session.url + path).openConnection() as HttpURLConnection).apply {
        requestMethod = method
        setRequestProperty("Authorization", "Bearer ${session.token}")
        setRequestProperty("Accept", "application/json")
        connectTimeout = 1500
        readTimeout = 5000
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
        conn.inputStream.bufferedReader().use { it.readText() }
      }
    } catch (_: Exception) {
      null
    } finally {
      connection?.disconnect()
    }
  }

  fun unlocked(context: Context): Boolean {
    val session = readSession(context) ?: return false
    val status = request(session, "GET", "/v1/status") ?: return false
    return !status.optBoolean("locked", true)
  }
}
