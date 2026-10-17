<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let conflicts = [];
  let error = '';
  let fixing = null;
  let fieldK = '';
  let fieldV = '';
  let detailId = null;
  let detail = null;
  let detailReveal = false;

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
      detailId = null;
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function show(id) {
    error = '';
    if (detailId === id) {
      detailId = null;
      detail = null;
      return;
    }
    try {
      detail = await api.conflict(id, detailReveal);
      detailId = id;
    } catch (e) {
      error = e.message;
    }
  }

  async function toggleReveal() {
    detailReveal = !detailReveal;
    if (detailId) {
      try {
        detail = await api.conflict(detailId, detailReveal);
      } catch (e) {
        error = e.message;
      }
    }
  }

  function values(d, target) {
    if (!d) return ['', ''];
    if (target.startsWith('field:')) {
      const k = target.slice(6);
      return [d.local.fields[k] ?? '', d.remote.fields[k] ?? ''];
    }
    if (target === 'name') return [d.local.name, d.remote.name];
    if (target === 'folder') return [d.local.folder, d.remote.folder];
    return ['', ''];
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
  <h2>Conflicts</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#each conflicts as c (c.item)}
    <div class="card">
      <div class="row">
        <a href={`/items/${c.item}`}>{c.item}</a>
        <span class="dim">{c.targets.join(', ')}</span>
        <span style="flex: 1"></span>
        <button on:click={() => show(c.item)}>{detailId === c.item ? 'Hide' : 'Details'}</button>
      </div>
      {#if detailId === c.item && detail}
        <div class="row"><button on:click={toggleReveal}>{detailReveal ? 'Mask' : 'Reveal'}</button></div>
        {#each detail.targets as t}
          {@const pair = values(detail, t)}
          <div class="card row">
            <strong>{t}</strong>
            <span>mine: {pair[0]}</span>
            <span>theirs: {pair[1]}</span>
          </div>
        {/each}
      {/if}
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
