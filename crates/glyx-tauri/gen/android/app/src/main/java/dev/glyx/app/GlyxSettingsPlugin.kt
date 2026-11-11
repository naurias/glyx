package dev.glyx.app

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.provider.Settings
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@TauriPlugin
class GlyxSettingsPlugin(private val host: Activity) : Plugin(host) {
  @Command
  fun info(invoke: Invoke) {
    val result = JSObject()
    result.put("sdk", Build.VERSION.SDK_INT)
    result.put("passkeys", Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    invoke.resolve(result)
  }

  @Command
  fun openAutofillSettings(invoke: Invoke) {
    open(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
    invoke.resolve(JSObject().put("ok", true))
  }

  @Command
  fun openCredentialSettings(invoke: Invoke) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      invoke.reject("Passkey settings require Android 14 or newer")
      return
    }
    open(Settings.ACTION_CREDENTIAL_PROVIDER)
    invoke.resolve(JSObject().put("ok", true))
  }

  private fun open(action: String) {
    host.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
  }
}
