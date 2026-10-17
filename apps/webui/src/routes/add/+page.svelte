<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import ItemForm from '$lib/ItemForm.svelte';

  let templates = [];
  let item_type = 'login';
  let name = '';
  let folder = '';
  let error = '';
  let busy = false;

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

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
  <a href="/exports">Exports</a>
  <a href="/settings">Settings</a>
  <a href="/onboarding">Vaults</a>
  <span style="flex: 1"></span>
</nav>
<main>
  <h2>Add item</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if templates.length}
    <ItemForm
      {templates}
      bind:item_type
      bind:name
      bind:folder
      submitLabel="Create"
      {busy}
      onsubmit={save}
    />
    {#if item_type === 'ssh_key'}
      <div class="row" style="margin-top: 12px">
        <button on:click={genSsh} disabled={busy}>Generate SSH key pair</button>
      </div>
    {/if}
  {/if}
</main>
