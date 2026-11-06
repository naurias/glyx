<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PromptDialog from '$lib/components/PromptDialog.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';

  let library = { tags: {}, folders: {} };
  let error = '';
  let notice = '';

  let promptOpen = false;
  let promptTitle = '';
  let promptLabel = '';
  let promptValue = '';
  let promptConfirmLabel = 'Save';
  let promptAction = () => {};

  let confirmOpen = false;
  let confirmTitle = '';
  let confirmMessage = '';
  let confirmLabel = 'Delete';
  let confirmDanger = true;
  let confirmAction = () => {};

  async function load() {
    error = '';
    try {
      library = await api.library();
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  function askPrompt(title, label, value, confirmLabel, action) {
    promptTitle = title;
    promptLabel = label;
    promptValue = value;
    promptConfirmLabel = confirmLabel;
    promptAction = action;
    promptOpen = true;
  }

  function submitPrompt(value) {
    const action = promptAction;
    promptOpen = false;
    action(value);
  }

  function askConfirm(title, message, label, action) {
    confirmTitle = title;
    confirmMessage = message;
    confirmLabel = label;
    confirmDanger = true;
    confirmAction = action;
    confirmOpen = true;
  }

  function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    action();
  }

  function renameTag(name) {
    askPrompt('Rename tag', 'New tag name', name, 'Rename', async (value) => {
      if (!value || value.trim() === name) return;
      try {
        await api.renameTag(name, value.trim());
        notice = `Tag renamed to ${value.trim()}`;
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }

  function removeTag(name) {
    askConfirm('Remove tag?', `Remove "${name}" from all items?`, 'Remove', async () => {
      try {
        await api.deleteTag(name);
        notice = `Tag "${name}" removed`;
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }

  function renameFolder(name) {
    askPrompt('Rename folder', 'New folder name', name, 'Rename', async (value) => {
      if (!value || value.trim() === name) return;
      try {
        await api.renameFolder(name, value.trim());
        notice = `Folder renamed to ${value.trim()}`;
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }

  function removeFolder(name) {
    askConfirm('Delete folder?', `Delete "${name}"? Its items move to the root.`, 'Delete', async () => {
      try {
        await api.deleteFolder(name);
        notice = `Folder "${name}" removed`;
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }
</script>

<PageHeader title="Tags & folders" subtitle="Library metadata is synced with the vault; renaming applies to every live item.">
  <svelte:fragment slot="actions">
    <a class="badge" href="/items">Back to items</a>
  </svelte:fragment>
</PageHeader>

{#if error}<p style="color: var(--danger)">{error}</p>{/if}
{#if notice}<p class="dim">{notice}</p>{/if}

<div class="detail-grid">
  <section>
    <div class="section-title"><h3>Folders</h3><span class="dim">{Object.keys(library.folders || {}).length}</span></div>
    {#if Object.keys(library.folders || {}).length}
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Folder</th><th>Items</th><th></th></tr></thead>
          <tbody>
            {#each Object.entries(library.folders) as [name, count]}
              <tr>
                <td class="item-name">{name}</td>
                <td class="dim">{count}</td>
                <td class="cell-actions">
                  <button on:click={() => renameFolder(name)}>Rename</button>
                  <button class="danger" on:click={() => removeFolder(name)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty"><strong>No folders yet.</strong><span>Add a folder name while creating or editing an item.</span></div>
    {/if}
  </section>

  <section>
    <div class="section-title"><h3>Tags</h3><span class="dim">{Object.keys(library.tags || {}).length}</span></div>
    {#if Object.keys(library.tags || {}).length}
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Tag</th><th>Items</th><th></th></tr></thead>
          <tbody>
            {#each Object.entries(library.tags) as [name, count]}
              <tr>
                <td class="item-name">#{name}</td>
                <td class="dim">{count}</td>
                <td class="cell-actions">
                  <button on:click={() => renameTag(name)}>Rename</button>
                  <button class="danger" on:click={() => removeTag(name)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty"><strong>No tags yet.</strong><span>Tags are comma-separated on each item.</span></div>
    {/if}
  </section>
</div>

<PromptDialog
  bind:open={promptOpen}
  title={promptTitle}
  label={promptLabel}
  value={promptValue}
  confirmLabel={promptConfirmLabel}
  onconfirm={submitPrompt}
  onclose={() => (promptOpen = false)}
/>
<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmTitle}
  message={confirmMessage}
  confirmLabel={confirmLabel}
  danger={confirmDanger}
  onconfirm={runConfirm}
  onclose={() => (confirmOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
