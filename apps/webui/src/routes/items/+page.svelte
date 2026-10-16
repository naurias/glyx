<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let items = [];
  let q = '';
  let error = '';

  async function load() {
    try {
      items = await api.items();
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
  $: filtered = items.filter(
    (i) => !q || i.name.toLowerCase().includes(q.toLowerCase()) || i.type.includes(q.toLowerCase())
  );
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
  <span style="flex: 1"></span>
  <button on:click={lock}>Lock</button>
</nav>
<main>
  <div class="row">
    <input bind:value={q} autofocus placeholder="Search name or type" />
  </div>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#each filtered as item (item.id)}
    <div class="card row">
      <span class="dim">{item.type}</span>
      <a href={`/items/${item.id}`}>{item.name}</a>
      {#if item.deleted}<span class="dim">[deleted]</span>{/if}
      <span style="flex: 1"></span>
      <span class="dim">rev {item.rev}</span>
    </div>
  {/each}
  {#if !filtered.length}<p class="dim">No items. <a href="/add">Add one</a>.</p>{/if}
</main>
