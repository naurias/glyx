<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let status = null;
  let report = null;
  let error = '';

  async function load() {
    try {
      status = await api.status();
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
  async function sync() {
    error = '';
    try {
      report = await api.sync({});
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function gc(dry) {
    error = '';
    try {
      report = await api.gc({ dry_run: dry });
    } catch (e) {
      error = e.message;
    }
  }
  async function doctor() {
    error = '';
    try {
      report = await api.doctor();
    } catch (e) {
      error = e.message;
    }
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Settings</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if status}
    <div class="card">
      <div>Envelopes: {status.envelopes} · live: {status.live} · conflicts: {status.conflicts}</div>
      <div class="dim">Last merge: {status.last_merge_ms ?? 'never'}</div>
    </div>
  {/if}
  <div class="row">
    <button on:click={sync}>Sync now</button>
    <button on:click={() => gc(true)}>GC dry run</button>
    <button on:click={() => gc(false)}>GC 30d</button>
    <button on:click={doctor}>Doctor</button>
  </div>
  {#if report}<pre class="card">{JSON.stringify(report, null, 2)}</pre>{/if}
</main>
