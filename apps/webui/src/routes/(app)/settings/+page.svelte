<script>
  import { api, isMobile } from '$lib/api.js';
  import { onMount } from 'svelte';
  let status = null;
  let report = null;
  let error = '';
  let settings = null;
  let notice = '';
  let rekey = {
    password: '',
    keyfile: '',
    no_keyfile: false,
    cipher: '',
    preset: '',
    keep_old_slots: false
  };
  let peer = { path: '', keyfile: '', password: '' };
  let gcDays = 30;
  let rebuildIndex = false;
  let withUnlock = false;
  let sshSock = '';
  let idleLockMin = '';
  let desktopSettings = null;
  let desktopNotice = '';
  let restoreFile = null;
  let restoreDest = '';
  let restoreInput = null;
  let backupBusy = false;
  let mobile = isMobile();
  let biometric = null;
  let bioBusy = false;
  let bioNotice = '';

  async function load() {
    try {
      status = await api.status();
      settings = await api.settings();
      idleLockMin = settings.idle_lock_min ?? 15;
      if (!mobile && window.__TAURI__?.core?.invoke) {
        desktopSettings = await window.__TAURI__.core.invoke('desktop_settings_get');
      }
      if (mobile) await loadBiometric();
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);

  async function loadBiometric() {
    if (!mobile || !window.__TAURI__?.core?.invoke) return;
    try {
      biometric = await window.__TAURI__.core.invoke('mobile_biometric_status');
    } catch {
      biometric = null;
    }
  }

  async function enableBiometric() {
    error = '';
    bioNotice = '';
    bioBusy = true;
    let slot = null;
    try {
      slot = await api.addBiometricSlot();
      await window.__TAURI__.core.invoke('mobile_biometric_enable', {
        secret: slot.secret,
        vaultId: status.vault.vault_id,
        slotId: slot.slot_id
      });
      slot.secret = '';
      bioNotice = 'Biometric unlock enabled.';
      await loadBiometric();
    } catch (e) {
      if (slot?.slot_id) {
        try {
          await api.retireBiometricSlot(slot.slot_id);
        } catch {
          /* best effort */
        }
      }
      error = e.message;
    } finally {
      bioBusy = false;
    }
  }

  async function disableBiometric() {
    error = '';
    bioNotice = '';
    bioBusy = true;
    try {
      if (biometric?.slot_id) await api.retireBiometricSlot(biometric.slot_id);
      await window.__TAURI__.core.invoke('mobile_biometric_disable');
      bioNotice = 'Biometric unlock disabled.';
      await loadBiometric();
    } catch (e) {
      error = e.message;
    } finally {
      bioBusy = false;
    }
  }

  async function saveDesktop() {
    error = '';
    desktopNotice = '';
    try {
      desktopSettings = await window.__TAURI__.core.invoke('desktop_settings_set', {
        settings: desktopSettings
      });
      desktopNotice = 'Desktop settings saved.';
    } catch (e) {
      error = e.message;
    }
  }
  async function setExit(value) {
    error = '';
    try {
      settings = await api.saveSettings({ daemon_on_exit: value });
    } catch (e) {
      error = e.message;
    }
  }
  async function setAuto(value) {
    error = '';
    try {
      settings = await api.saveSettings({ auto_materialize: value });
    } catch (e) {
      error = e.message;
    }
  }
  async function setLockOnExit(value) {
    error = '';
    try {
      settings = await api.saveSettings({ lock_on_exit: value });
    } catch (e) {
      error = e.message;
    }
  }
  async function setMode(value) {
    error = '';
    try {
      settings = await api.saveSettings({ mode: value });
    } catch (e) {
      error = e.message;
    }
  }
  async function saveTtl() {
    error = '';
    try {
      settings = await api.saveSettings({ session_ttl_min: Number(settings.session_ttl_min) });
    } catch (e) {
      error = e.message;
    }
  }
  async function saveIdleLock() {
    error = '';
    try {
      settings = await api.saveSettings({ idle_lock_min: Number(idleLockMin) || 0 });
    } catch (e) {
      error = e.message;
    }
  }
  async function doRekey() {
    error = '';
    notice = '';
    try {
      const body = {};
      if (rekey.password) body.password = rekey.password;
      if (rekey.keyfile) body.keyfile = rekey.keyfile;
      if (rekey.no_keyfile) body.no_keyfile = true;
      if (rekey.cipher) body.cipher = rekey.cipher;
      if (rekey.preset) body.preset = rekey.preset;
      if (rekey.keep_old_slots) body.keep_old_slots = true;
      await api.rekey(body);
      notice = 'Credentials rotated. Unlock again to confirm.';
      rekey = {
        password: '',
        keyfile: '',
        no_keyfile: false,
        cipher: '',
        preset: '',
        keep_old_slots: false
      };
    } catch (e) {
      error = e.message;
    }
  }
  async function sync() {
    error = '';
    try {
      report = await api.sync({});
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function syncPeer() {
    error = '';
    notice = '';
    try {
      const body = { other: peer.path };
      if (peer.keyfile) body.other_keyfile = peer.keyfile;
      if (peer.password) body.other_password = peer.password;
      report = await api.sync(body);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function loadSshEnv() {
    error = '';
    try {
      const r = await api.sshEnv();
      sshSock = r.sock;
    } catch (e) {
      sshSock = '';
      error = e.message;
    }
  }
  async function gc(dry) {
    error = '';
    try {
      report = await api.gc({ dry_run: dry, older_than_ms: Number(gcDays) * 86400000 });
    } catch (e) {
      error = e.message;
    }
  }
  async function gcBlobs(dry) {
    error = '';
    try {
      report = await api.gcBlobs(dry);
    } catch (e) {
      error = e.message;
    }
  }
  async function backup() {
    error = '';
    notice = '';
    backupBusy = true;
    try {
      await api.backup();
      notice = 'Backup downloaded.';
    } catch (e) {
      error = e.message;
    } finally {
      backupBusy = false;
    }
  }
  async function restore() {
    if (!restoreFile) {
      error = 'Choose a backup file first.';
      return;
    }
    if (!restoreDest) {
      error = 'Choose a new vault file path.';
      return;
    }
    error = '';
    notice = '';
    backupBusy = true;
    try {
      const result = await api.restore(restoreFile, restoreDest);
      notice = `Restored to ${result.path}. Unlock it to rebuild the index.`;
      restoreFile = null;
      restoreDest = '';
      if (restoreInput) restoreInput.value = '';
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      backupBusy = false;
    }
  }
  async function doctor() {
    error = '';
    try {
      const params = {};
      if (rebuildIndex) params.rebuild_index = true;
      if (withUnlock) params.with_unlock = true;
      report = await api.doctor(params);
    } catch (e) {
      error = e.message;
    }
  }
</script>

<div class="page">
  <h2>Settings</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if status}
    <div class="card">
      <div>Envelopes: {status.envelopes} · live: {status.live} · conflicts: {status.conflicts}</div>
      <div class="dim">Last merge: {status.last_merge_ms ?? 'never'}</div>
    </div>
  {/if}
  {#if settings}
    <div class="card">
      <div>When the desktop app closes:</div>
      <div class="row">
        <button class:selected={settings.daemon_on_exit === 'stop'} on:click={() => setExit('stop')}>
          Stop the daemon
        </button>
        <button class:selected={settings.daemon_on_exit === 'keep'} on:click={() => setExit('keep')}>
          Keep it running
        </button>
      </div>
      <p class="dim">Stopping on exit is more private; keeping it running keeps the browser, Git, and SSH agent working.</p>
    </div>
    <div class="card">
      <div>On unlock:</div>
      <div class="row">
        <button class:selected={settings.auto_materialize} on:click={() => setAuto(true)}>
          Materialize all tracked files
        </button>
        <button class:selected={!settings.auto_materialize} on:click={() => setAuto(false)}>
          Lock until I unlock each
        </button>
      </div>
      <p class="dim">With auto off, unlock writes no secrets to disk; use the Exports page (or CLI) to unlock individual targets.</p>
    </div>
    <div class="card">
      <div>On crash or exit:</div>
      <div class="row">
        <button class:selected={settings.lock_on_exit} on:click={() => setLockOnExit(true)}>
          Lock in-place files
        </button>
        <button class:selected={!settings.lock_on_exit} on:click={() => setLockOnExit(false)}>
          Leave them as-is
        </button>
      </div>
      <p class="dim">Applies to tracked in-place files when the daemon exits or recovers after a crash. Each file can override this from the Files page.</p>
    </div>
    <div class="card">
      <div>Session</div>
      <div class="row">
        <button class:selected={settings.mode === 'oneshot'} on:click={() => setMode('oneshot')}>
          One-shot
        </button>
        <button class:selected={settings.mode === 'session'} on:click={() => setMode('session')}>
          Session
        </button>
      </div>
      <div class="row">
        <label class="row">TTL minutes
          <input type="number" min="1" max="480" bind:value={settings.session_ttl_min} />
        </label>
        <button on:click={saveTtl}>Save TTL</button>
      </div>
      <div class="row">
        <label class="row">Idle auto-lock minutes (0 disables)
          <input type="number" min="0" bind:value={idleLockMin} style="width: 5rem" />
        </label>
        <button on:click={saveIdleLock}>Save idle lock</button>
      </div>
      <p class="dim">Session mode stores the data key under 0600 in the runtime dir until the TTL expires; one-shot prompts every time.</p>
    </div>
    <div class="card">
      <div>Backup</div>
      <p class="dim">Lock the vault first. The backup is a direct copy of the encrypted <code>.glyx</code> file; the device id and keyfile are never included.</p>
      <div class="row">
        <button on:click={backup} disabled={backupBusy}>Download backup</button>
      </div>
      <div class="row">
        <input type="file" bind:this={restoreInput} on:change={(e) => (restoreFile = e.currentTarget.files?.[0] ?? null)} />
        <input bind:value={restoreDest} placeholder="/path/to/restored.glyx" style="flex: 1" />
        <button on:click={restore} disabled={backupBusy}>Restore</button>
      </div>
    </div>
    <div class="card">
      <div>Attachments</div>
      <p class="dim">Orphaned encrypted blobs are never purged automatically.</p>
      <div class="row">
        <button on:click={() => gcBlobs(true)}>List orphan blobs</button>
        <button class="danger" on:click={() => gcBlobs(false)}>Purge orphan blobs</button>
      </div>
    </div>
    <div class="card">
      <div>Rotate credentials (vault must be unlocked)</div>
      <label>New password<input type="password" bind:value={rekey.password} /></label>
      <div class="row">
        <label class="row"><input type="checkbox" bind:checked={rekey.no_keyfile} /> drop keyfile</label>
        <input bind:value={rekey.keyfile} placeholder="keyfile path (or new)" style="flex: 1" />
      </div>
      <div class="row">
        <select bind:value={rekey.cipher}>
          <option value="">cipher: keep</option>
          <option value="xchacha">xchacha</option>
          <option value="aesgcm">aesgcm</option>
        </select>
        <select bind:value={rekey.preset}>
          <option value="">preset: keep</option>
          <option value="balanced">balanced</option>
          <option value="hardened">hardened</option>
          <option value="mobile">mobile</option>
        </select>
        <label class="row"><input type="checkbox" bind:checked={rekey.keep_old_slots} /> keep old slots</label>
        <button class="primary" on:click={doRekey}>Rotate</button>
      </div>
      {#if notice}<p class="dim">{notice}</p>{/if}
    </div>
  {/if}
  {#if mobile && biometric?.available}
    <div class="card">
      <div>Biometric unlock</div>
      {#if status?.vault?.keyfile_required}
        <p class="dim">Not available for keyfile-required vaults.</p>
      {:else if status?.locked}
        <p class="dim">Unlock the vault first.</p>
      {:else if biometric.enabled && biometric.vault_id === status?.vault?.vault_id}
        <p class="dim">Enabled for this vault. The key is stored in Android Keystore and requires biometric authentication.</p>
        <button on:click={disableBiometric} disabled={bioBusy}>Disable biometric unlock</button>
      {:else}
        <p class="dim">Enable after unlocking. The key is stored in Android Keystore and requires biometric authentication.</p>
        <button on:click={enableBiometric} disabled={bioBusy}>Enable biometric unlock</button>
      {/if}
      {#if bioNotice}<p class="dim">{bioNotice}</p>{/if}
    </div>
  {/if}
  {#if desktopSettings}
    <div class="card">
      <div>Desktop</div>
      <label class="row">
        <input type="checkbox" bind:checked={desktopSettings.close_to_tray} /> close to tray
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={desktopSettings.autostart} /> start on login (minimized)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={desktopSettings.notifications} /> desktop notifications
      </label>
      <div class="row">
        <label class="row">quick-search shortcut
          <input bind:value={desktopSettings.shortcut} placeholder="Ctrl+Shift+G" style="flex: 1" />
        </label>
        <button class="primary" on:click={saveDesktop}>Save desktop settings</button>
      </div>
      {#if desktopNotice}<p class="dim">{desktopNotice}</p>{/if}
      {#if !desktopSettings.close_to_tray}
        <p class="dim">Closing the window quits glyx and follows the daemon-on-exit setting.</p>
      {/if}
    </div>
  {/if}
  <div class="card">
    <div>Sync and maintenance</div>
    <div class="row">
      <button on:click={sync}>Sync now</button>
      <button on:click={() => gc(true)}>GC dry run</button>
      <button on:click={() => gc(false)}>GC purge</button>
      <label class="row">window days<input type="number" min="1" bind:value={gcDays} style="width: 5rem" /></label>
      <label class="row"><input type="checkbox" bind:checked={rebuildIndex} /> rebuild index</label>
      <label class="row"><input type="checkbox" bind:checked={withUnlock} /> with unlock</label>
      <button on:click={doctor}>Doctor</button>
    </div>
    <p class="dim">Rebuild index needs the vault locked; lock from Items, run Doctor, then unlock.</p>
  </div>
  <div class="card">
    <div>Pairwise sync with another vault copy</div>
    <label>Other vault path<input bind:value={peer.path} placeholder="/path/to/other.glyx" /></label>
    <div class="row">
      <input bind:value={peer.keyfile} placeholder="other keyfile (if required)" style="flex: 1" />
      <input type="password" bind:value={peer.password} placeholder="other password" style="flex: 1" />
    </div>
    <div class="row">
      <button on:click={syncPeer} disabled={!peer.path}>Sync with other vault</button>
    </div>
  </div>
  <div class="card">
    <div>SSH agent</div>
    <div class="row">
      <button on:click={loadSshEnv}>Show agent socket</button>
      {#if sshSock}<code style="flex: 1">{sshSock}</code>{/if}
    </div>
    <p class="dim">In a shell run <code>eval $(glyx ssh agent-env)</code>. The socket exists only while the vault is unlocked.</p>
  </div>
  {#if report}<pre class="card">{JSON.stringify(report, null, 2)}</pre>{/if}
</div>
