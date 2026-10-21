<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let groups = [];
  let error = '';
  let notice = '';

  async function load() {
    error = '';
    try {
      groups = (await api.duplicates()).groups || [];
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  async function removeGroup(group) {
    if (!confirm(`Delete ${group.items.length} items in this group?`)) return;
    try {
      const ids = group.items.map((item) => item.id);
      const result = await api.bulk({ ids, action: 'delete' });
      notice = `deleted ${result.affected} item(s)`;
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
  <a href="/exports">Exports</a>
  <a href="/settings">Settings</a>
  <a href="/onboarding">Vaults</a>
</nav>
<main>
  <h2>Possible duplicates</h2>
  <p class="dim">Grouped by normalized name or login URL + username. Passwords are never shown here.</p>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if notice}<p class="dim">{notice}</p>{/if}
  {#if !groups.length}<p class="dim">No duplicates found.</p>{/if}
  {#each groups as group, index (index)}
    <div class="card">
      <div class="row">
        <strong>Group {index + 1}</strong>
        <span class="dim">{group.reason.join(' + ')}{group.same_password ? ' · same password' : ''}</span>
        <span style="flex: 1"></span>
        <button class="danger" on:click={() => removeGroup(group)}>Delete group</button>
      </div>
      {#each group.items as item (item.id)}
        <div class="row">
          <span class="dim">{item.type}</span>
          <a href={`/items/${item.id}`}>{item.favorite ? '★ ' : ''}{item.name}</a>
          {#if item.folder}<span class="dim">· {item.folder}</span>{/if}
        </div>
      {/each}
    </div>
  {/each}
</main>
