<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import ItemForm from '$lib/ItemForm.svelte';
  import PointerEditor from '$lib/components/PointerEditor.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import { parseOtpauth } from '$lib/totp.js';
  import { totpCapture } from '$lib/totp-capture.js';

  let templates = [];
  let item_type = 'login';
  let name = '';
  let folder = '';
  let error = '';
  let busy = false;
  let allItems = [];
  let pointerFields = {};
  let pointerTags = '';
  let pointerEditor = null;
  let totpSeed = '';

  const labels = {
    login: ['Login', 'Username, password, URL, and notes'],
    passkey: ['Passkey', 'Synced WebAuthn credential'],
    totp: ['TOTP', 'One-time-password seed'],
    identity: ['Identity', 'Name, email, phone, address'],
    card: ['Card', 'Payment card details'],
    note: ['Note', 'Markdown with secret references'],
    file: ['File', 'Encrypted attachment'],
    ssh_key: ['SSH key', 'Ed25519 or RSA key pair'],
    generic_key: ['Generic key', 'Any other secret material'],
    pointer: ['Pointer', 'Named aliases to other item fields']
  };

  onMount(() => {
    const stop = totpCapture.subscribe((uri) => {
      if (!uri) return;
      item_type = 'totp';
      totpSeed = uri;
      const parsed = parseOtpauth(uri);
      if (parsed && !name.trim()) {
        name = parsed.issuer
          ? parsed.account
            ? `${parsed.issuer} (${parsed.account})`
            : parsed.issuer
          : parsed.account || '';
      }
      totpCapture.set('');
    });
    load();
    return stop;
  });

  async function load() {
    try {
      [templates, allItems] = await Promise.all([api.templates(), api.items()]);
    } catch (e) {
      error = e.message;
    }
  }

  async function autoLinkTotp(id, seed) {
    const parsed = parseOtpauth(seed || '');
    const query = (parsed?.issuer || parsed?.account || '').trim();
    if (!query) return;
    try {
      const rows = await api.items({ q: query, type: 'login' });
      const logins = rows.filter((row) => row.type === 'login');
      if (logins.length === 1) await api.link(logins[0].id, id);
    } catch {
      // Linking is best-effort; the TOTP is already saved.
    }
  }

  async function save(payload) {
    error = '';
    busy = true;
    try {
      const res = await api.create(payload);
      if (payload.type === 'totp') await autoLinkTotp(res.id, payload.fields?.seed);
      goto(`/items/${res.id}`);
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function genSsh() {
    error = '';
    busy = true;
    try {
      const res = await api.sshGen({ name: name || 'ssh key', folder });
      goto(`/items/${res.id}`);
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function savePointer() {
    error = '';
    if (!name.trim()) {
      error = 'Name is required.';
      return;
    }
    const fields = pointerEditor?.fields() || {};
    if (!Object.keys(fields).length) {
      error = 'Add at least one alias with a target item and field.';
      return;
    }
    busy = true;
    try {
      const res = await api.create({
        type: 'pointer',
        name,
        folder,
        tags: pointerTags
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean),
        fields
      });
      goto(`/items/${res.id}`);
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="Add item" subtitle="Choose a type, then fill in the fields. Extra fields are allowed on any type.">
  <svelte:fragment slot="actions">
    <a class="badge" href="/items">Back to items</a>
  </svelte:fragment>
</PageHeader>

{#if error}<p style="color: var(--danger)">{error}</p>{/if}

{#if templates.length}
  <div class="type-grid">
    {#each templates as t}
      {@const meta = labels[t.type] || [t.type, '']}
      <button
        class:active={item_type === t.type}
        class="type-card"
        on:click={() => (item_type = t.type)}
      >
        <span class={`badge ${t.type}`}>{t.type.replaceAll('_', ' ')}</span>
        <strong>{meta[0]}</strong>
        <span class="dim">{meta[1]}</span>
      </button>
    {/each}
  </div>

  <div class="card">
    {#if item_type === 'pointer'}
      <label>Name<input bind:value={name} /></label>
      <label>Folder<input bind:value={folder} /></label>
      <label>Tags<input bind:value={pointerTags} placeholder="comma, separated" /></label>
      <PointerEditor items={allItems} bind:this={pointerEditor} onchange={(fields) => (pointerFields = fields)} />
      <div class="row" style="margin-top: 8px">
        <button class="primary" on:click={savePointer} disabled={busy}>Create pointer item</button>
      </div>
    {:else}
      {#key totpSeed}
        <ItemForm
          {templates}
          bind:item_type
          bind:name
          bind:folder
          values={totpSeed ? { seed: totpSeed } : {}}
          submitLabel="Create item"
          {busy}
          onsubmit={save}
        />
      {/key}
      {#if item_type === 'ssh_key'}
        <div class="row" style="margin-top: 12px">
          <button on:click={genSsh} disabled={busy}>Generate SSH key pair instead</button>
        </div>
      {/if}
    {/if}
  </div>
{/if}
