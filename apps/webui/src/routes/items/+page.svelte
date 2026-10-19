<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let items = [];
  let q = '';
  let type = '';
  let folder = '';
  let tag = '';
  let showDeleted = false;
  let error = '';
  let timer;

  async function load() {
    error = '';
    try {
      const params = {};
      if (type) params.type = type;
      if (folder) params.folder = folder;
      if (tag) params.tag = tag;
      if (q) params.q = q;
      if (showDeleted) params.all = true;
      items = await api.items(params);
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
  function debounced() {
    clearTimeout(timer);
    timer = setTimeout(load, 200);
  }
  async function lock() {
    await api.lock();
    goto('/');
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
  <button on:click={lock}>Lock</button>
</nav>
<main>
  <div class="row">
    <input bind:value={q} on:input={debounced} autofocus placeholder="Search name, folder, tags, fields" style="flex: 1" />
    <input bind:value={type} placeholder="type" />
    <input bind:value={folder} placeholder="folder" />
    <input bind:value={tag} placeholder="tag" />
    <label class="row"><input type="checkbox" bind:checked={showDeleted} /> deleted</label>
    <button on:click={load}>Apply</button>
  </div>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#each items as item (item.id)}
    <div class="card row">
      <span class="dim">{item.type}</span>
      <a href={`/items/${item.id}`}>{item.name}</a>
      {#if item.deleted}<span class="dim">[deleted]</span>{/if}
      <span style="flex: 1"></span>
      <span class="dim">rev {item.rev}</span>
    </div>
  {/each}
  {#if !items.length}<p class="dim">No items. <a href="/add">Add one</a>.</p>{/if}
</main>
