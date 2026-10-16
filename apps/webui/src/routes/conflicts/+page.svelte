<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let conflicts = [];
  let error = '';
  let fixing = null;
  let fieldK = '';
  let fieldV = '';

  async function load() {
    try {
      conflicts = await api.conflicts();
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
  async function resolve(id, mode, fields) {
    try {
      await api.resolve(id, { mode, fields });
      fixing = null;
      await load();
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
  <h2>Conflicts</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#each conflicts as c (c.item)}
    <div class="card">
      <div class="row">
        <a href={`/items/${c.item}`}>{c.item}</a>
        <span class="dim">{c.targets.join(', ')}</span>
      </div>
      <div class="row" style="margin-top: 8px">
        <button on:click={() => resolve(c.item, 'mine')}>Keep mine</button>
        <button on:click={() => resolve(c.item, 'theirs')}>Keep theirs</button>
        <button on:click={() => (fixing = fixing === c.item ? null : c.item)}>Set field</button>
      </div>
      {#if fixing === c.item}
        <div class="row" style="margin-top: 8px">
          <input bind:value={fieldK} placeholder="field" />
          <input bind:value={fieldV} placeholder="value" style="flex: 1" />
          <button class="primary" on:click={() => resolve(c.item, 'fields', { [fieldK]: fieldV })}>Apply</button>
        </div>
      {/if}
    </div>
  {/each}
  {#if !conflicts.length}<p class="dim">No conflicts. Merges are quiet when devices agree.</p>{/if}
</main>
