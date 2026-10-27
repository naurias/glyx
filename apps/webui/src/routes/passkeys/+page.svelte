<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let passkeys = [];
  let error = '';
  let notice = '';

  async function load() {
    error = '';
    try {
      passkeys = await api.passkeys();
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  function fmt(ms) {
    return ms ? new Date(ms).toLocaleString() : 'never';
  }

  async function rename(item) {
    const name = prompt('Passkey name', item.name);
    if (!name || name === item.name) return;
    error = '';
    try {
      await api.edit(item.item_id, { rename: name });
      notice = 'Passkey renamed.';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function remove(item) {
    if (!confirm(`Delete the passkey for ${item.rp_id}?`)) return;
    error = '';
    try {
      await api.remove(item.item_id);
      notice = 'Passkey deleted. The relying party may still list it until it cleans up.';
      await load();
    } catch (e) {
      error = e.message;
    }
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/passkeys">Passkeys</a>
  <a href="/health">Health</a>
  <a href="/audit">Audit</a>
  <a href="/devices">Devices</a>
  <a href="/generator">Generator</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Passkeys</h2>
  <p class="dim">
    Passkeys are stored as synced vault items. The Chromium extension creates and uses them
    through WebAuthn; this page only manages metadata. Private keys are never displayed.
  </p>
  <div class="card">
    <div class="row">
      <strong>Browser integration</strong>
      <span style="flex: 1"></span>
      <span class="dim">Chromium only</span>
    </div>
    <p class="dim">
      Enable <strong>Passkeys</strong> in the glyx extension popup to attach it as the WebAuthn
      provider. Only one extension can be attached at a time. Firefox and Safari do not expose
      an equivalent provider API; desktop OS passkey providers are not implemented.
    </p>
  </div>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if notice}<p class="dim">{notice}</p>{/if}
  {#each passkeys as item (item.item_id)}
    <div class="card">
      <div class="row">
        <strong>{item.name}</strong>
        <span class="dim">{item.rp_id}</span>
        <span style="flex: 1"></span>
        {#if !item.usable}<span style="color: var(--danger)">missing private key</span>{/if}
        <span class="dim">{item.discoverable ? 'discoverable' : 'non-discoverable'}</span>
      </div>
      <div class="row dim">
        <span>{item.user_name || item.display_name || 'no username'}</span>
        <span>{item.algorithm || 'ES256'} · sign count {item.sign_count ?? 0}</span>
        <span style="flex: 1"></span>
        <span>created {fmt(item.created_ms)}</span>
        <span>used {fmt(item.last_used_ms)}</span>
      </div>
      <div class="row">
        <span class="dim">{item.backup_eligible ? 'synced/backed up' : 'device-bound'}</span>
        <span style="flex: 1"></span>
        <button on:click={() => rename(item)}>Rename</button>
        <button class="danger" on:click={() => remove(item)}>Delete</button>
      </div>
    </div>
  {/each}
  {#if !passkeys.length}<p class="dim">No passkeys stored yet. Create one from a Chromium site with the extension passkey provider enabled.</p>{/if}
</main>
