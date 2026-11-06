<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import ItemForm from '$lib/ItemForm.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';

  let templates = [];
  let item_type = 'login';
  let name = '';
  let folder = '';
  let error = '';
  let busy = false;

  const labels = {
    login: ['Login', 'Username, password, URL, and notes'],
    passkey: ['Passkey', 'Synced WebAuthn credential'],
    totp: ['TOTP', 'One-time-password seed'],
    identity: ['Identity', 'Name, email, phone, address'],
    card: ['Card', 'Payment card details'],
    note: ['Note', 'Markdown with secret references'],
    file: ['File', 'Encrypted attachment'],
    ssh_key: ['SSH key', 'Ed25519 or RSA key pair'],
    generic_key: ['Generic key', 'Any other secret material']
  };

  onMount(async () => {
    try {
      templates = await api.templates();
    } catch (e) {
      error = e.message;
    }
  });

  async function save(payload) {
    error = '';
    busy = true;
    try {
      const res = await api.create(payload);
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
    <ItemForm
      {templates}
      bind:item_type
      bind:name
      bind:folder
      submitLabel="Create item"
      {busy}
      onsubmit={save}
    />
    {#if item_type === 'ssh_key'}
      <div class="row" style="margin-top: 12px">
        <button on:click={genSsh} disabled={busy}>Generate SSH key pair instead</button>
      </div>
    {/if}
  </div>
{/if}
