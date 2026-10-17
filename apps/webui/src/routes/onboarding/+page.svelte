<script>
  import { api, configured, bootstrapDesktop } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let vaults = [];
  let current = null;
  let error = '';
  let mode = 'list';
  let addPath = '';
  let addKeyfile = '';
  let form = { path: '', name: '', preset: 'balanced', cipher: 'xchacha', password: '', keyfile: '' };

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

  onMount(async () => {
    bootstrapDesktop();
    if (configured()) await load();
  });

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
    try {
      await api.addVault({ path: addPath, keyfile: addKeyfile || undefined });
      addPath = '';
      addKeyfile = '';
      mode = 'list';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function create() {
    error = '';
    try {
      await api.createVault({
        path: form.path,
        name: form.name || undefined,
        preset: form.preset,
        cipher: form.cipher,
        password: form.password,
        keyfile: form.keyfile || undefined
      });
      goto('/');
    } catch (e) {
      error = e.message;
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
  {#if !configured()}
    <p class="dim">Connect to the daemon first on the <a href="/">home page</a>.</p>
  {:else}
    {#if mode === 'list'}
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
          <button on:click={() => select(v.path)}>Use</button>
          <button class="danger" on:click={() => forget(v.path)}>Forget</button>
        </div>
      {/each}
      {#if !vaults.length}
        <p class="dim">No vaults yet. Add one from a custom location or create a new vault.</p>
      {/if}
      <div class="row">
        <button on:click={() => (mode = 'add')}>Add from custom location</button>
        <button on:click={() => (mode = 'create')}>Create and configure new vault</button>
      </div>
    {:else if mode === 'add'}
      <label>Vault directory<input bind:value={addPath} placeholder="/path/to/vault.glyx" /></label>
      <label>Keyfile path (optional)<input bind:value={addKeyfile} /></label>
      <div class="row">
        <button class="primary" on:click={add}>Add</button>
        <button on:click={() => (mode = 'list')}>Cancel</button>
      </div>
    {:else}
      <label>New vault directory<input bind:value={form.path} placeholder="/path/to/new.glyx" /></label>
      <label>Display name (optional)<input bind:value={form.name} /></label>
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
      <label>Password<input type="password" bind:value={form.password} /></label>
      <label>Keyfile path (optional, recommended)<input bind:value={form.keyfile} /></label>
      <div class="row">
        <button class="primary" on:click={create}>Create</button>
        <button on:click={() => (mode = 'list')}>Cancel</button>
      </div>
    {/if}
  {/if}
</main>
