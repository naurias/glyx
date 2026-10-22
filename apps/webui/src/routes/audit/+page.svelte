<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let events = [];
  let total = 0;
  let limit = 50;
  let offset = 0;
  let eventFilter = '';
  let error = '';

  async function load() {
    error = '';
    try {
      const params = { limit, offset };
      if (eventFilter) params.event = eventFilter;
      const result = await api.audit(params);
      events = result.data.events || [];
      total = result.total || events.length;
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  function apply() {
    offset = 0;
    load();
  }

  function page(next) {
    offset = Math.max(0, offset + next * limit);
    load();
  }

  function time(ms) {
    return new Date(ms).toLocaleString();
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/devices">Devices</a>
  <a href="/health">Health</a>
  <a href="/generator">Generator</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Audit log</h2>
  <p class="dim">Local to this device. No item names or secret values are recorded.</p>
  <div class="row">
    <input bind:value={eventFilter} placeholder="event filter" />
    <button on:click={apply}>Filter</button>
    <span style="flex: 1"></span>
    <button on:click={() => page(-1)} disabled={offset === 0}>Previous</button>
    <span class="dim">{offset + 1}-{offset + events.length} of {total}</span>
    <button on:click={() => page(1)} disabled={offset + events.length >= total}>Next</button>
  </div>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#each events as event}
    <div class="card row">
      <span class="dim">{time(event.ts_ms)}</span>
      <strong>{event.event}</strong>
      <span>{event.outcome || ''}</span>
      {#if event.item_id}<span class="dim">{event.item_id.slice(0, 8)}</span>{/if}
      {#if event.field}<span class="dim">{event.field}</span>{/if}
      {#if event.detail}<span class="dim">{event.detail}</span>{/if}
    </div>
  {/each}
  {#if !events.length}<p class="dim">No audit events.</p>{/if}
</main>
