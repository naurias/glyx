package dev.glyx.app

import android.content.Context
import android.os.Build
import android.util.Base64
import androidx.credentials.provider.CallingAppInfo
import java.security.MessageDigest

object PasskeyOrigin {
  private const val PREFIX = "android:apk-key-hash:"

  fun forCallingApp(context: Context, info: CallingAppInfo?): String {
    if (info == null) return PREFIX
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      val allowlist = runCatching {
        context.resources
          .openRawResource(R.raw.glyx_privileged_apps)
          .bufferedReader()
          .use { it.readText() }
      }.getOrNull()
      if (!allowlist.isNullOrBlank()) {
        val origin = runCatching { info.getOrigin(allowlist) }.getOrNull()
        if (!origin.isNullOrBlank()) return origin
      }
    }
    return apkOrigin(info)
  }

  fun apkOrigin(info: CallingAppInfo): String {
    val certificate = runCatching {
      info.signingInfo.apkContentsSigners.firstOrNull()?.toByteArray()
    }.getOrNull() ?: return PREFIX
    val digest = MessageDigest.getInstance("SHA-256").digest(certificate)
    val encoded = Base64.encodeToString(
      digest,
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )
    return PREFIX + encoded
  }
}
