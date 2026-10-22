<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let report = { summary: {}, issues: [] };
  let minLength = 12;
  let maxAgeDays = 365;
  let error = '';

  async function load() {
    error = '';
    try {
      report = await api.health({ min_length: minLength, max_age_days: maxAgeDays });
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/devices">Devices</a>
  <a href="/audit">Audit</a>
  <a href="/generator">Generator</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Password health</h2>
  <div class="row">
    <label>Min length <input type="number" min="1" max="128" bind:value={minLength} style="width: 5rem" /></label>
    <label>Max age (days) <input type="number" min="0" max="3650" bind:value={maxAgeDays} style="width: 6rem" /></label>
    <button on:click={load}>Scan</button>
  </div>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  <div class="card row">
    <span>items <strong>{report.summary.items || 0}</strong></span>
    <span>weak <strong>{report.summary.weak || 0}</strong></span>
    <span>reused <strong>{report.summary.reused || 0}</strong></span>
    <span>old <strong>{report.summary.old || 0}</strong></span>
    <span>no TOTP <strong>{report.summary.no_totp || 0}</strong></span>
  </div>
  {#each report.issues as issue (issue.id)}
    <div class="card row">
      <span class="dim">{issue.item_type}</span>
      <a href={`/items/${issue.id}`}>{issue.name}</a>
      <span style="flex: 1"></span>
      <span>{issue.issues.join(', ')}</span>
    </div>
  {/each}
  {#if !report.issues.length}<p class="dim">No issues found.</p>{/if}
</main>
