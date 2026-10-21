<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let items = [];
  let total = 0;
  let q = '';
  let type = '';
  let folder = '';
  let tag = '';
  let showDeleted = false;
  let favoritesOnly = false;
  let sort = 'updated';
  let order = 'desc';
  let page = 0;
  let pageSize = 50;
  let selected = new Set();
  let library = { tags: {}, folders: {} };
  let recents = [];
  let error = '';
  let notice = '';
  let timer;
  $: totalPages = Math.max(1, Math.ceil(total / pageSize));
  $: selectedCount = selected.size;
  $: allSelected = items.length > 0 && items.every((item) => selected.has(item.id));

  async function loadItems() {
    error = '';
    try {
      const params = { limit: pageSize, offset: page * pageSize, sort, order };
      if (type) params.type = type;
      if (folder) params.folder = folder;
      if (tag) params.tag = tag;
      if (q) params.q = q;
      if (showDeleted) params.all = true;
      if (favoritesOnly) params.favorite = true;
      const result = await api.itemsPage(params);
      items = result.data;
      total = result.total;
      const maxPage = Math.max(0, Math.ceil(total / pageSize) - 1);
      if (page > maxPage) {
        page = maxPage;
        await loadItems();
      }
    } catch (e) {
      error = e.message;
    }
  }

  async function loadMeta() {
    try {
      const [lib, recent] = await Promise.all([api.library(), api.recents()]);
      library = lib;
      recents = recent.slice(0, 6);
    } catch (e) {
      error = e.message;
    }
  }

  onMount(async () => {
    await Promise.all([loadItems(), loadMeta()]);
  });

  function debounced() {
    clearTimeout(timer);
    timer = setTimeout(applyFilters, 200);
  }

  function applyFilters() {
    page = 0;
    selected = new Set();
    loadItems();
  }

  function changeSort() {
    order = ['updated', 'favorite'].includes(sort) ? 'desc' : 'asc';
    applyFilters();
  }

  function goPage(next) {
    page = Math.max(0, Math.min(totalPages - 1, next));
    selected = new Set();
    loadItems();
  }

  function toggleSelect(id) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selected = next;
  }

  function toggleAll() {
    const next = new Set(selected);
    if (allSelected) items.forEach((item) => next.delete(item.id));
    else items.forEach((item) => next.add(item.id));
    selected = next;
  }

  async function toggleFavorite(item) {
    try {
      await api.edit(item.id, { favorite: !item.favorite });
      item.favorite = !item.favorite;
      items = items;
      if (favoritesOnly && !item.favorite) await loadItems();
      await loadMeta();
    } catch (e) {
      error = e.message;
    }
  }

  async function bulk(action, payload = {}) {
    if (!selectedCount) return;
    if (action === 'delete' && !confirm(`Delete ${selectedCount} item(s)? Tombstones are kept for sync.`)) return;
    error = '';
    notice = '';
    try {
      const ids = [...selected];
      const result = await api.bulk({ ids, action, ...payload });
      notice = `${action.replace('_', ' ')}: ${result.affected} item(s)`;
      selected = new Set();
      await Promise.all([loadItems(), loadMeta()]);
    } catch (e) {
      error = e.message;
    }
  }

  async function addTagBulk() {
    const value = prompt('Tag to add');
    if (value) await bulk('add_tags', { tags: [value.trim()] });
  }

  async function removeTagBulk() {
    const value = prompt('Tag to remove');
    if (value) await bulk('remove_tags', { tags: [value.trim()] });
  }

  async function moveBulk() {
    const value = prompt('Destination folder (empty for root)');
    if (value !== null) await bulk('set_folder', { folder: value.trim() });
  }

  async function renameTag(name) {
    const to = prompt(`Rename tag "${name}" to`, name);
    if (!to || to === name) return;
    try {
      await api.renameTag(name, to.trim());
      await Promise.all([loadItems(), loadMeta()]);
    } catch (e) {
      error = e.message;
    }
  }

  async function removeTag(name) {
    if (!confirm(`Remove tag "${name}" from all items?`)) return;
    try {
      await api.deleteTag(name);
      await Promise.all([loadItems(), loadMeta()]);
    } catch (e) {
      error = e.message;
    }
  }

  async function renameFolder(name) {
    const to = prompt(`Rename folder "${name}" to`, name);
    if (!to || to === name) return;
    try {
      await api.renameFolder(name, to.trim());
      await Promise.all([loadItems(), loadMeta()]);
    } catch (e) {
      error = e.message;
    }
  }

  async function removeFolder(name) {
    if (!confirm(`Delete folder "${name}"? Items move to the root.`)) return;
    try {
      await api.deleteFolder(name);
      await Promise.all([loadItems(), loadMeta()]);
    } catch (e) {
      error = e.message;
    }
  }

  async function lock() {
    await api.lock();
    goto('/');
  }

  function fmtTime(ms) {
    return ms ? new Date(ms).toLocaleDateString() : '';
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
  <button on:click={lock}>Lock</button>
</nav>
<main>
  {#if recents.length}
    <div class="card">
      <div class="row"><strong>Recents</strong><span style="flex: 1"></span><span class="dim">local only</span></div>
      <div class="row" style="flex-wrap: wrap">
        {#each recents as recent (recent.id)}
          <a href={`/items/${recent.id}`}>{recent.favorite ? '★ ' : ''}{recent.name}</a>
        {/each}
      </div>
    </div>
  {/if}

  <div class="row">
    <input bind:value={q} on:input={debounced} autofocus placeholder="Search name, folder, tags, fields" style="flex: 1" />
    <select bind:value={type} on:change={applyFilters}>
      <option value="">all types</option>
      <option value="login">login</option>
      <option value="passkey">passkey</option>
      <option value="totp">totp</option>
      <option value="identity">identity</option>
      <option value="card">card</option>
      <option value="note">note</option>
      <option value="file">file</option>
      <option value="ssh_key">ssh_key</option>
      <option value="generic_key">generic_key</option>
    </select>
    <select bind:value={folder} on:change={applyFilters}>
      <option value="">all folders</option>
      {#each Object.keys(library.folders) as name}
        <option value={name}>{name}</option>
      {/each}
    </select>
    <select bind:value={tag} on:change={applyFilters}>
      <option value="">all tags</option>
      {#each Object.keys(library.tags) as name}
        <option value={name}>{name}</option>
      {/each}
    </select>
    <select bind:value={sort} on:change={changeSort}>
      <option value="updated">updated</option>
      <option value="name">name</option>
      <option value="type">type</option>
      <option value="favorite">favorite</option>
    </select>
    <select bind:value={order} on:change={applyFilters}>
      <option value="desc">desc</option>
      <option value="asc">asc</option>
    </select>
    <label class="row"><input type="checkbox" bind:checked={favoritesOnly} on:change={applyFilters} /> favorites</label>
    <label class="row"><input type="checkbox" bind:checked={showDeleted} on:change={applyFilters} /> deleted</label>
  </div>

  <details class="card">
    <summary>Library · {Object.keys(library.folders).length} folders · {Object.keys(library.tags).length} tags</summary>
    {#if !Object.keys(library.tags).length && !Object.keys(library.folders).length}
      <p class="dim">No tags or folders yet.</p>
    {/if}
    {#each Object.entries(library.tags) as [name, count]}
      <div class="row">
        <span>tag</span><strong>{name}</strong><span class="dim">{count}</span>
        <span style="flex: 1"></span>
        <button on:click={() => renameTag(name)}>Rename</button>
        <button class="danger" on:click={() => removeTag(name)}>Remove</button>
      </div>
    {/each}
    {#each Object.entries(library.folders) as [name, count]}
      <div class="row">
        <span>folder</span><strong>{name}</strong><span class="dim">{count}</span>
        <span style="flex: 1"></span>
        <button on:click={() => renameFolder(name)}>Rename</button>
        <button class="danger" on:click={() => removeFolder(name)}>Remove</button>
      </div>
    {/each}
  </details>

  <p><a href="/items/duplicates">Review possible duplicates</a></p>

  {#if selectedCount}
    <div class="card row">
      <strong>{selectedCount} selected</strong>
      <button on:click={() => bulk('favorite')}>Favorite</button>
      <button on:click={() => bulk('unfavorite')}>Unfavorite</button>
      <button on:click={addTagBulk}>Add tag</button>
      <button on:click={removeTagBulk}>Remove tag</button>
      <button on:click={moveBulk}>Move</button>
      <span style="flex: 1"></span>
      <button class="danger" on:click={() => bulk('delete')}>Delete</button>
      <button on:click={() => (selected = new Set())}>Clear</button>
    </div>
  {/if}

  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if notice}<p class="dim">{notice}</p>{/if}

  <div class="row">
    <label class="row"><input type="checkbox" checked={allSelected} on:change={toggleAll} /> select page</label>
    <span class="dim">{total} item(s)</span>
    <span style="flex: 1"></span>
    <button on:click={() => goPage(page - 1)} disabled={page === 0}>Previous</button>
    <span class="dim">{page + 1} / {totalPages}</span>
    <button on:click={() => goPage(page + 1)} disabled={page + 1 >= totalPages}>Next</button>
    <select bind:value={pageSize} on:change={applyFilters}>
      <option value={25}>25</option>
      <option value={50}>50</option>
      <option value={100}>100</option>
    </select>
  </div>

  {#each items as item (item.id)}
    <div class="card row">
      <input type="checkbox" checked={selected.has(item.id)} on:change={() => toggleSelect(item.id)} />
      <button title="Favorite" on:click={() => toggleFavorite(item)}>{item.favorite ? '★' : '☆'}</button>
      <span class="dim">{item.type}</span>
      <a href={`/items/${item.id}`}>{item.name}</a>
      {#if item.deleted}<span class="dim">[deleted]</span>{/if}
      {#if item.folder}<span class="dim">· {item.folder}</span>{/if}
      {#if item.tags?.length}<span class="dim">· {item.tags.join(', ')}</span>{/if}
      <span style="flex: 1"></span>
      <span class="dim">{fmtTime(item.updated_ms)} · rev {item.rev}</span>
    </div>
  {/each}
  {#if !items.length}<p class="dim">No items. <a href="/add">Add one</a>.</p>{/if}
</main>
