<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PromptDialog from '$lib/components/PromptDialog.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';

  let passkeys = [];
  let error = '';
  let notice = '';

  let promptOpen = false;
  let promptValue = '';
  let promptItem = null;
  let confirmOpen = false;
  let confirmItem = null;

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

  function rename(item) {
    promptItem = item;
    promptValue = item.name;
    promptOpen = true;
  }

  async function saveName(name) {
    promptOpen = false;
    if (!promptItem || !name || name === promptItem.name) return;
    error = '';
    try {
      await api.edit(promptItem.item_id, { rename: name });
      notice = 'Passkey renamed';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  function remove(item) {
    confirmItem = item;
    confirmOpen = true;
  }

  async function confirmRemove() {
    confirmOpen = false;
    if (!confirmItem) return;
    error = '';
    try {
      await api.remove(confirmItem.item_id);
      notice = 'Passkey deleted. The relying party may still list it until it cleans up.';
      await load();
    } catch (e) {
      error = e.message;
    }
  }
</script>

<PageHeader
  title="Passkeys"
  subtitle="Stored as synced vault items. The Chromium extension creates and uses them through WebAuthn; this page manages metadata only."
/>

{#if error}<p style="color: var(--danger)">{error}</p>{/if}

<div class="card">
  <div class="row">
    <strong>Browser integration</strong>
    <span style="flex: 1"></span>
    <span class="chip">Chromium only</span>
  </div>
  <p class="dim">
    Enable <strong>Passkeys</strong> in the glyx extension popup to attach it as the WebAuthn
    provider. Only one extension can be attached at a time. Firefox and Safari do not expose an
    equivalent provider API; desktop OS passkey providers are not implemented.
  </p>
</div>

{#each passkeys as item (item.item_id)}
  <div class="card">
    <div class="row">
      <strong>{item.name}</strong>
      <span class="chip">{item.rp_id}</span>
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
      <a class="chip" href={`/items/${item.item_id}`}>Open</a>
      <button on:click={() => rename(item)}>Rename</button>
      <button class="danger" on:click={() => remove(item)}>Delete</button>
    </div>
  </div>
{/each}
{#if !passkeys.length}
  <div class="empty">
    <strong>No passkeys stored yet.</strong>
    <span>Create one from a Chromium site with the extension passkey provider enabled.</span>
  </div>
{/if}

<PromptDialog
  bind:open={promptOpen}
  title="Rename passkey"
  label="Name"
  value={promptValue}
  confirmLabel="Rename"
  onconfirm={saveName}
  onclose={() => (promptOpen = false)}
/>
<ConfirmDialog
  bind:open={confirmOpen}
  title="Delete passkey?"
  message={confirmItem ? `Delete the passkey for ${confirmItem.rp_id}?` : ''}
  confirmLabel="Delete"
  danger
  onconfirm={confirmRemove}
  onclose={() => (confirmOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
