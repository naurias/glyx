<script>
  import {
    api,
    configured,
    bootstrapDesktop,
    bootstrapError,
    retryDesktopBootstrap,
    pickFolder,
    pickSave,
    isMobile,
    mobileDataDir
  } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  let vaults = [];
  let current = null;
  let error = '';
  let notice = '';
  let mode = 'list';
  let booting = false;
  let bootError = '';
  let addPath = '';
  let addName = '';
  let addKeyfile = '';
  let createParent = '';
  let createName = 'glyx';
  let createKeyfile = '';
  let password = '';
  let confirm = '';
  let restoreParent = '';
  let restoreName = 'restored';
  let restoreInput = null;
  let restoring = false;
  let busy = false;
  let mobile = isMobile();

  let form = { preset: 'balanced', cipher: 'xchacha' };

  $: slug = (value) =>
    (value || 'vault')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'vault';
  $: createPath = createParent
    ? `${createParent.replace(/\/+$/, '')}/${slug(createName)}.glyx`
    : '';
  $: restorePath = restoreParent
    ? `${restoreParent.replace(/\/+$/, '')}/${slug(restoreName)}.glyx`
    : '';

  async function load() {
    error = '';
    try {
      const data = await api.vaults();
      vaults = data.vaults || [];
      current = data.current;
    } catch (e) {
      error = e.message;
    }
  }

  async function ensureDesktop() {
    bootstrapDesktop();
    if (!configured() && window.__TAURI__?.core?.invoke) {
      booting = true;
      const ok = await retryDesktopBootstrap();
      booting = false;
      bootError = ok ? '' : bootstrapError();
    }
    return configured();
  }

  onMount(async () => {
    if (mobile) {
      const base = mobileDataDir() ? `${mobileDataDir()}/vaults` : 'vaults';
      if (!createParent) createParent = base;
      if (!restoreParent) restoreParent = base;
    }
    if (await ensureDesktop()) await load();
  });

  async function retry() {
    bootError = '';
    booting = true;
    const ok = await retryDesktopBootstrap();
    booting = false;
    if (!ok) {
      bootError = bootstrapError() || 'daemon did not start';
      return;
    }
    await load();
  }

  async function chooseAddFolder() {
    const path = await pickFolder('Select an existing glyx vault folder');
    if (path) addPath = path;
  }

  async function chooseCreateFolder() {
    const path = await pickFolder('Select the parent folder for the new vault');
    if (path) createParent = path;
  }

  async function chooseKeyfile() {
    const path = await pickSave('Choose a keyfile location', 'glyx.key');
    if (path) createKeyfile = path;
  }

  async function chooseRestoreFolder() {
    const path = await pickFolder('Select the parent folder for the restored vault');
    if (path) restoreParent = path;
  }

  async function forget(path) {
    error = '';
    if (!confirm(`Forget ${path}? The vault files are not deleted.`)) return;
    try {
      await api.forgetVault(path);
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function select(path) {
    error = '';
    try {
      await api.selectVault(path);
      goto('/');
    } catch (e) {
      error = e.message;
    }
  }

  async function add() {
    error = '';
    if (!addPath) {
      error = 'Choose an existing vault folder first.';
      return;
    }
    busy = true;
    try {
      await api.addVault({
        path: addPath,
        name: addName || undefined,
        keyfile: addKeyfile || undefined
      });
      await api.selectVault(addPath);
      goto('/');
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function create() {
    error = '';
    if (!createPath) {
      error = 'Choose a parent folder for the new vault.';
      return;
    }
    if (password.length < 1) {
      error = 'Enter a password.';
      return;
    }
    if (password !== confirm) {
      error = 'Passwords do not match.';
      return;
    }
    busy = true;
    try {
      await api.createVault({
        path: createPath,
        name: createName || undefined,
        preset: form.preset,
        cipher: form.cipher,
        password,
        keyfile: createKeyfile || undefined
      });
      try {
        await api.unlock(password, createKeyfile || undefined);
        password = '';
        confirm = '';
        goto('/items');
      } catch {
        password = '';
        confirm = '';
        goto('/');
      }
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function restore() {
    error = '';
    const file = restoreInput?.files?.[0];
    if (!file) {
      error = 'Choose a glyx backup archive first.';
      return;
    }
    if (!restorePath) {
      error = 'Choose a parent folder for the restored vault.';
      return;
    }
    restoring = true;
    try {
      await api.restore(file, restorePath);
      await api.selectVault(restorePath);
      goto('/');
    } catch (e) {
      error = e.message;
    } finally {
      restoring = false;
    }
  }
</script>

<nav>
  <a href="/">Home</a>
  <span style="flex: 1"></span>
</nav>
<main>
  <h1>Vaults</h1>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if notice}<p class="dim">{notice}</p>{/if}
  {#if booting}
    <p class="dim">Starting the glyx daemon...</p>
  {:else if bootError}
    <div class="card">
      <p style="color: var(--danger)">Could not start the glyx daemon.</p>
      <p class="dim">{bootError}</p>
      <button class="primary" on:click={retry}>Retry</button>
    </div>
  {:else if !configured()}
    <p class="dim">Connect to the daemon first on the <a href="/">home page</a>.</p>
  {:else}
    {#if mode === 'list'}
      <p class="dim">Choose a vault to continue, or open/create one below.</p>
      {#each vaults as v (v.path)}
        <div class="card row">
          <div>
            <strong>{v.label}</strong>
            {#if v.current}<span class="dim"> (current)</span>{/if}
            <div class="dim"><code>{v.path}</code></div>
            {#if v.keyfile_required}<div class="dim">keyfile required</div>{/if}
            {#if !v.valid}<div style="color: var(--danger)">{v.error}</div>{/if}
          </div>
          <span style="flex: 1"></span>
          <button class="primary" on:click={() => select(v.path)} disabled={!v.valid}>Use</button>
          <button class="danger" on:click={() => forget(v.path)}>Forget</button>
        </div>
      {/each}
      {#if !vaults.length}
        <div class="card">
          <strong>Welcome to glyx</strong>
          <p class="dim">Create a new vault, open one synced from another device, or restore a backup.</p>
        </div>
      {/if}
      <div class="row" style="flex-wrap: wrap">
        <button on:click={() => (mode = 'create')}>Create new vault</button>
        <button on:click={() => (mode = 'add')}>Open existing vault</button>
        <button on:click={() => (mode = 'restore')}>Restore from backup</button>
      </div>
    {:else if mode === 'add'}
      <h2>Open existing vault</h2>
      <p class="dim">Select a glyx vault folder you created here or synced from another device.</p>
      <label>Vault folder
        <div class="row">
          <input bind:value={addPath} placeholder="/path/to/vault.glyx" style="flex: 1" />
          <button on:click={chooseAddFolder}>Browse...</button>
        </div>
      </label>
      <label>Display name (optional)<input bind:value={addName} placeholder="Personal" /></label>
      <label>Keyfile path (optional)
        <input bind:value={addKeyfile} placeholder="/path/to/keyfile" />
      </label>
      <div class="row">
        <button class="primary" on:click={add} disabled={busy}>Open vault</button>
        <button on:click={() => (mode = 'list')}>Cancel</button>
      </div>
    {:else if mode === 'create'}
      <h2>Create new vault</h2>
      <p class="dim">The vault directory must not exist yet. Your password is mandatory; a keyfile adds a second factor.</p>
      <label>Parent folder
        <div class="row">
          <input bind:value={createParent} placeholder="/home/you/Vaults" style="flex: 1" />
          <button on:click={chooseCreateFolder}>Browse...</button>
        </div>
      </label>
      <label>Vault name<input bind:value={createName} /></label>
      {#if createPath}<p class="dim">Will create <code>{createPath}</code></p>{/if}
      <label>KDF preset
        <select bind:value={form.preset}>
          <option value="balanced">balanced</option>
          <option value="hardened">hardened</option>
          <option value="mobile">mobile</option>
        </select>
      </label>
      <label>Cipher
        <select bind:value={form.cipher}>
          <option value="xchacha">xchacha</option>
          <option value="aesgcm">aesgcm</option>
        </select>
      </label>
      <label>Password<input type="password" bind:value={password} /></label>
      <label>Confirm password<input type="password" bind:value={confirm} /></label>
      <label>Keyfile path (optional, recommended)
        <div class="row">
          <input bind:value={createKeyfile} placeholder="/path/to/new.key" style="flex: 1" />
          <button on:click={chooseKeyfile}>Browse...</button>
        </div>
      </label>
      <div class="row">
        <button class="primary" on:click={create} disabled={busy}>Create and unlock</button>
        <button on:click={() => (mode = 'list')}>Cancel</button>
      </div>
    {:else}
      <h2>Restore from backup</h2>
      <p class="dim">Restore a glyx backup archive into a new vault directory.</p>
      <label>Backup archive<input type="file" bind:this={restoreInput} accept=".gz,.tgz,.tar.gz" /></label>
      <label>Parent folder
        <div class="row">
          <input bind:value={restoreParent} placeholder="/home/you/Vaults" style="flex: 1" />
          <button on:click={chooseRestoreFolder}>Browse...</button>
        </div>
      </label>
      <label>Vault name<input bind:value={restoreName} /></label>
      {#if restorePath}<p class="dim">Will restore to <code>{restorePath}</code></p>{/if}
      <div class="row">
        <button class="primary" on:click={restore} disabled={restoring}>
          {restoring ? 'Restoring...' : 'Restore vault'}
        </button>
        <button on:click={() => (mode = 'list')}>Cancel</button>
      </div>
    {/if}
  {/if}
</main>
