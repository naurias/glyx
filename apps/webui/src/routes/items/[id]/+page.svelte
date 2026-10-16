<script>
  import { api } from '$lib/api.js';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let item = null;
  let reveal = false;
  let error = '';
  let code = '';
  $: id = $page.params.id;

  async function load() {
    try {
      item = await api.show(id, reveal);
      code = '';
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
  async function toggle() {
    reveal = !reveal;
    await load();
  }
  async function totp() {
    try {
      const r = await api.totp(id);
      code = r.code;
    } catch (e) {
      error = e.message;
    }
  }
  async function remove() {
    if (!confirm('Delete this item (tombstone kept for sync)?')) return;
    await api.remove(id);
    goto('/items');
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if item}
    <h2>{item.name} <span class="dim">[{item.type}]</span></h2>
    <p class="dim">{item.id} · rev {item.rev}{item.folder ? ` · ${item.folder}` : ''}</p>
    {#each Object.entries(item.fields) as [k, v]}
      <div class="card row"><strong>{k}</strong><span>{v}</span></div>
    {/each}
    <div class="row">
      <button on:click={toggle}>{reveal ? 'Mask' : 'Reveal'}</button>
      {#if item.type === 'totp'}<button on:click={totp}>TOTP code</button>{/if}
      <button class="danger" on:click={remove}>Delete</button>
    </div>
    {#if code}<p>Code: <strong>{code}</strong></p>{/if}
  {/if}
</main>
