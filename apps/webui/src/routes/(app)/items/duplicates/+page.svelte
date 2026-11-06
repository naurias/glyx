<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';

  let groups = [];
  let error = '';
  let notice = '';
  let pending = null;
  let confirmOpen = false;

  async function load() {
    error = '';
    try {
      groups = (await api.duplicates()).groups || [];
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  function askRemove(group) {
    pending = group;
    confirmOpen = true;
  }

  async function removeGroup() {
    confirmOpen = false;
    if (!pending) return;
    try {
      const ids = pending.items.map((item) => item.id);
      const result = await api.bulk({ ids, action: 'delete' });
      notice = `Deleted ${result.affected} item(s)`;
      await load();
    } catch (e) {
      error = e.message;
    }
  }
</script>

<PageHeader title="Possible duplicates" subtitle="Grouped by normalized name or login URL + username. Passwords are never shown here." />

{#if error}<p style="color: var(--danger)">{error}</p>{/if}
{#if !groups.length}
  <div class="empty"><strong>No duplicates found.</strong><span>Your library looks tidy.</span></div>
{/if}
{#each groups as group, index (index)}
  <div class="card">
    <div class="row">
      <strong>Group {index + 1}</strong>
      <span class="dim">{group.reason.join(' + ')}{group.same_password ? ' · same password' : ''}</span>
      <span style="flex: 1"></span>
      <button class="danger" on:click={() => askRemove(group)}>Delete group</button>
    </div>
    {#each group.items as item (item.id)}
      <div class="row">
        <span class="badge {item.type}">{item.type.replaceAll('_', ' ')}</span>
        <a href={`/items/${item.id}`}>{item.favorite ? '★ ' : ''}{item.name}</a>
        {#if item.folder}<span class="dim">· {item.folder}</span>{/if}
      </div>
    {/each}
  </div>
{/each}

<ConfirmDialog
  bind:open={confirmOpen}
  title="Delete duplicate group?"
  message={pending ? `Delete ${pending.items.length} item(s)? Tombstones are kept for sync.` : ''}
  confirmLabel="Delete"
  danger
  onconfirm={removeGroup}
  onclose={() => (confirmOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
