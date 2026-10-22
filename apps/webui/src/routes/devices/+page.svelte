<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let devices = [];
  let error = '';

  async function load() {
    error = '';
    try {
      devices = (await api.devices()).devices || [];
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  async function rename(device) {
    const label = prompt(`Label for ${device.id.slice(0, 8)}`, device.label);
    if (!label || label === device.label) return;
    try {
      await api.labelDevice(device.id, label);
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  function seen(ms) {
    return ms ? new Date(ms).toLocaleString() : 'never';
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/health">Health</a>
  <a href="/audit">Audit</a>
  <a href="/generator">Generator</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Devices</h2>
  <p class="dim">Last seen is the newest write activity observed in this vault, not online presence. Labels are local to this device.</p>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#each devices as device (device.id)}
    <div class="card row">
      <strong>{device.label}</strong>
      {#if device.current}<span class="dim">current</span>{/if}
      <span class="dim">{device.id}</span>
      <span style="flex: 1"></span>
      <span class="dim">{seen(device.last_seen_ms)}</span>
      <button on:click={() => rename(device)}>Rename</button>
    </div>
  {/each}
  {#if !devices.length}<p class="dim">No devices observed yet.</p>{/if}
</main>
