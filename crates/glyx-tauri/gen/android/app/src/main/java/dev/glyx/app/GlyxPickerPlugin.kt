package dev.glyx.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File

@InvokeArg
class PickTitleArgs {
  var title: String? = null
}

@InvokeArg
class PickSaveArgs {
  var title: String? = null
  var fileName: String? = null
}

/**
 * Native file picking for the Android build.
 *
 * The desktop app opens a real filesystem dialog. Android's storage access
 * framework cannot hand out writable filesystem paths, so the pickers return
 * paths the in-process daemon can actually use:
 *
 * - [pickFile] opens `ACTION_OPEN_DOCUMENT`, copies the picked document into
 *   app-private storage and returns that path, so vault files, keyfiles and
 *   tracked files stay readable and writable by the daemon.
 * - [pickFolder] opens `ACTION_OPEN_DOCUMENT_TREE` and returns the app-private
 *   vault directory: scoped storage does not expose a writable directory path
 *   for a user location.
 * - [pickSave] returns a path under app storage, which is where exports and
 *   other generated files land on Android.
 *
 * Mirroring an export back to a user-visible location (share sheet) is a
 * follow-up.
 */
@TauriPlugin
class GlyxPickerPlugin(private val host: Activity) : Plugin(host) {
  @Command
  fun pickFile(invoke: Invoke) {
    val args = invoke.parseArgs(PickTitleArgs::class.java)
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "*/*"
      putExtra(Intent.EXTRA_TITLE, args.title ?: "Choose a file")
    }
    launch(invoke, intent, "onPickedFile")
  }

  @Command
  fun pickFolder(invoke: Invoke) {
    val args = invoke.parseArgs(PickTitleArgs::class.java)
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
      putExtra(Intent.EXTRA_TITLE, args.title ?: "Choose a file")
    }
    launch(invoke, intent, "onPickedFolder")
  }

  @Command
  fun pickSave(invoke: Invoke) {
    val args = invoke.parseArgs(PickSaveArgs::class.java)
    val dir = ensureDir(File(host.filesDir, "glyx-out"))
    if (dir == null) {
      invoke.reject("cannot create the glyx output directory")
      return
    }
    val name = safeComponent(args.fileName ?: "")
    invoke.resolve(JSObject().put("path", File(dir, name).absolutePath))
  }

  private fun launch(invoke: Invoke, intent: Intent, callback: String) {
    host.runOnUiThread { startActivityForResult(invoke, intent, callback) }
  }

  @ActivityCallback
  fun onPickedFile(invoke: Invoke, result: ActivityResult) {
    val uri = result.data?.data
    if (result.resultCode != Activity.RESULT_OK || uri == null) {
      invoke.resolve(JSObject().put("path", ""))
      return
    }
    val label = displayName(uri)
    stageInBackground(uri, label) { path ->
      invoke.resolve(JSObject().put("path", path))
    }
  }

  @ActivityCallback
  fun onPickedFolder(invoke: Invoke, result: ActivityResult) {
    if (result.resultCode != Activity.RESULT_OK) {
      invoke.resolve(JSObject().put("path", ""))
      return
    }
    val dir = ensureDir(File(host.filesDir, "vaults"))
    if (dir == null) {
      invoke.reject("cannot create the glyx vault directory")
      return
    }
    invoke.resolve(JSObject().put("path", dir.absolutePath))
  }

  private fun displayName(uri: Uri): String {
    val fromDoc = runCatching {
      host.contentResolver
        .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
    }.getOrNull()
    return fromDoc ?: uri.lastPathSegment ?: "glyx-file"
  }

  private fun stageInBackground(uri: Uri, label: String, done: (String) -> Unit) {
    Thread {
      val path = runCatching {
        val dir = ensureDir(File(host.filesDir, "glyx-in"))
          ?: error("cannot create the glyx-in directory")
        val target = File(dir, safeComponent(label))
        host.contentResolver.openInputStream(uri)?.use { input ->
          target.outputStream().use { output -> input.copyTo(output) }
        } ?: error("cannot read the picked document")
        target.absolutePath
      }.getOrElse { "" }
      host.runOnUiThread { done(path) }
    }.start()
  }

  private fun ensureDir(dir: File): File? =
    when {
      dir.isDirectory -> dir
      dir.mkdirs() -> dir
      else -> null
    }

  /** Reduce an untrusted name to a single safe path component. */
  private fun safeComponent(name: String): String {
    val cleaned = name.map { c ->
      if (c.isLetterOrDigit() || c == '.' || c == '-' || c == '_') c else '_'
    }.joinToString("")
    val trimmed = cleaned.trim('.', '_')
    return if (trimmed.isEmpty()) "glyx-file" else trimmed
  }
}