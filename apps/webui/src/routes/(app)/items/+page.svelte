<script>
  import { api } from '$lib/api.js';
  import { goto, afterNavigate, replaceState } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import FilterTree from '$lib/components/FilterTree.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PromptDialog from '$lib/components/PromptDialog.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';

  let items = [];
  let total = 0;
  let q = $page.url.searchParams.get('q') || '';
  let type = $page.url.searchParams.get('type') || '';
  let folder = $page.url.searchParams.get('folder') || '';
  let tag = $page.url.searchParams.get('tag') || '';
  let favoritesOnly = $page.url.searchParams.get('favorite') === '1';
  let recentsOnly = $page.url.searchParams.get('recents') === '1';
  let showDeleted = false;
  let sort = 'updated';
  let order = 'desc';
  let pageNo = 0;
  let pageSize = 50;
  let selected = new Set();
  let library = { tags: {}, folders: {} };
  let allItems = [];
  let groupChildren = true;
  let recents = [];
  let error = '';
  let notice = '';
  let timer;

  let promptOpen = false;
  let promptTitle = '';
  let promptLabel = '';
  let promptValue = '';
  let promptConfirmLabel = 'Save';
  let promptAction = () => {};

  let confirmOpen = false;
  let confirmTitle = '';
  let confirmMessage = '';
  let confirmLabel = 'Confirm';
  let confirmDanger = true;
  let confirmAction = () => {};

  $: totalPages = Math.max(1, Math.ceil(total / pageSize));
  $: selectedCount = selected.size;
  $: visibleItems = groupChildren
    ? items.filter((item) => !item.fields?.login_id)
    : items;
  $: allSelected = visibleItems.length > 0 && visibleItems.every((item) => selected.has(item.id));
  $: childCount = allItems.reduce((counts, item) => {
    const parent = item.fields?.login_id;
    if (parent) counts[parent] = (counts[parent] || 0) + 1;
    return counts;
  }, {});

  function syncUrl() {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (type) params.set('type', type);
    if (folder) params.set('folder', folder);
    if (tag) params.set('tag', tag);
    if (favoritesOnly) params.set('favorite', '1');
    if (recentsOnly) params.set('recents', '1');
    const qs = params.toString();
    replaceState(`/items${qs ? `?${qs}` : ''}`, {});
  }

  async function loadItems() {
    error = '';
    try {
      if (recentsOnly) {
        const [recent, all] = await Promise.all([api.recents(), api.items()]);
        const orderMap = new Map(recent.map((r, i) => [r.id, i]));
        let list = all.filter((item) => orderMap.has(item.id));
        if (q) {
          const needle = q.toLowerCase();
          list = list.filter(
            (item) =>
              item.name.toLowerCase().includes(needle) ||
              (item.folder || '').toLowerCase().includes(needle) ||
              (item.tags || []).some((t) => t.toLowerCase().includes(needle))
          );
        }
        if (type) list = list.filter((item) => item.type === type);
        if (folder) list = list.filter((item) => item.folder === folder);
        if (tag) list = list.filter((item) => (item.tags || []).includes(tag));
        if (favoritesOnly) list = list.filter((item) => item.favorite);
        list = list.filter((item) => !item.deleted || showDeleted);
        list.sort((a, b) => (orderMap.get(a.id) ?? 999) - (orderMap.get(b.id) ?? 999));
        total = list.length;
        items = list.slice(pageNo * pageSize, pageNo * pageSize + pageSize);
      } else {
        const params = { limit: pageSize, offset: pageNo * pageSize, sort, order };
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
        if (pageNo > maxPage) {
          pageNo = maxPage;
          await loadItems();
        }
      }
    } catch (e) {
      error = e.message;
    }
  }

  async function loadMeta() {
    try {
      const [lib, recent, all] = await Promise.all([
        api.library(),
        api.recents(),
        api.items()
      ]);
      library = lib;
      recents = recent.slice(0, 8);
      allItems = all;
    } catch (e) {
      error = e.message;
    }
  }

  function hydrateFromUrl() {
    const nextQ = $page.url.searchParams.get('q') || '';
    const nextType = $page.url.searchParams.get('type') || '';
    const nextFolder = $page.url.searchParams.get('folder') || '';
    const nextTag = $page.url.searchParams.get('tag') || '';
    const nextFavorite = $page.url.searchParams.get('favorite') === '1';
    const nextRecents = $page.url.searchParams.get('recents') === '1';
    if (
      nextQ !== q ||
      nextType !== type ||
      nextFolder !== folder ||
      nextTag !== tag ||
      nextFavorite !== favoritesOnly ||
      nextRecents !== recentsOnly
    ) {
      q = nextQ;
      type = nextType;
      folder = nextFolder;
      tag = nextTag;
      favoritesOnly = nextFavorite;
      recentsOnly = nextRecents;
      pageNo = 0;
      selected = new Set();
      loadItems();
    }
  }

  afterNavigate(hydrateFromUrl);

  onMount(async () => {
    await Promise.all([loadItems(), loadMeta()]);
  });

  function debounced() {
    clearTimeout(timer);
    timer = setTimeout(applyFilters, 200);
  }

  function applyFilters() {
    pageNo = 0;
    selected = new Set();
    syncUrl();
    loadItems();
  }

  function applyTree(next) {
    type = next.type;
    folder = next.folder;
    tag = next.tag;
    favoritesOnly = next.favoritesOnly;
    recentsOnly = next.recentsOnly;
    applyFilters();
  }

  function clearFilters() {
    type = '';
    folder = '';
    tag = '';
    favoritesOnly = false;
    recentsOnly = false;
    q = '';
    applyFilters();
  }

  function changeSort() {
    order = ['updated', 'favorite'].includes(sort) ? 'desc' : 'asc';
    applyFilters();
  }

  function goPage(next) {
    pageNo = Math.max(0, Math.min(totalPages - 1, next));
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
    if (allSelected) visibleItems.forEach((item) => next.delete(item.id));
    else visibleItems.forEach((item) => next.add(item.id));
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
    error = '';
    notice = '';
    try {
      const ids = [...selected];
      const result = await api.bulk({ ids, action, ...payload });
      notice = `${action.replaceAll('_', ' ')}: ${result.affected} item(s)`;
      selected = new Set();
      await Promise.all([loadItems(), loadMeta()]);
    } catch (e) {
      error = e.message;
    }
  }

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

  function askConfirm(title, message, label, danger, action) {
    confirmTitle = title;
    confirmMessage = message;
    confirmLabel = label;
    confirmDanger = danger;
    confirmAction = action;
    confirmOpen = true;
  }

  function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    action();
  }

  function addTagBulk() {
    askPrompt('Add tag', 'Tag name', '', 'Add tag', (value) => {
      if (value?.trim()) bulk('add_tags', { tags: [value.trim()] });
    });
  }

  function removeTagBulk() {
    askPrompt('Remove tag', 'Tag name', '', 'Remove tag', (value) => {
      if (value?.trim()) bulk('remove_tags', { tags: [value.trim()] });
    });
  }

  function moveBulk() {
    askPrompt('Move to folder', 'Destination folder (empty for root)', '', 'Move', (value) => {
      if (value !== null && value !== undefined) bulk('set_folder', { folder: value.trim() });
    });
  }

  function deleteBulk() {
    askConfirm(
      'Delete selected items?',
      `Delete ${selectedCount} item(s)? Tombstones are kept for sync.`,
      'Delete',
      true,
      () => bulk('delete')
    );
  }

  async function lock() {
    await api.lock();
    goto('/');
  }

  function fmtTime(ms) {
    return ms ? new Date(ms).toLocaleDateString() : '';
  }

  function itemSub(item) {
    const values = item.fields || {};
    return values.username || values.user_name || values.url || values.email || '';
  }
</script>

<PageHeader title="Items" subtitle={`${total} item(s) in this vault`}>
  <svelte:fragment slot="actions">
    <a class="badge" href="/add">+ Add item</a>
  </svelte:fragment>
</PageHeader>

<div class="items-layout">
  <FilterTree
    {type}
    {folder}
    {tag}
    {favoritesOnly}
    {recentsOnly}
    {library}
    {recents}
    onselect={applyTree}
  />

  <section class="items-pane">
    <div class="toolbar">
      <input type="search" bind:value={q} on:input={debounced} placeholder="Search name, folder, tags, fields" />
      <select bind:value={sort} on:change={changeSort} aria-label="Sort by">
        <option value="updated">Updated</option>
        <option value="name">Name</option>
        <option value="type">Type</option>
        <option value="favorite">Favorite</option>
      </select>
      <select bind:value={order} on:change={applyFilters} aria-label="Sort direction">
        <option value="desc">Descending</option>
        <option value="asc">Ascending</option>
      </select>
      <label class="row"><input type="checkbox" bind:checked={showDeleted} on:change={applyFilters} /> Deleted</label>
      <label class="row"><input type="checkbox" bind:checked={groupChildren} /> Group linked</label>
      <button class="ghost" on:click={clearFilters}>Clear</button>
    </div>

    {#if error}<p style="color: var(--danger)">{error}</p>{/if}
    {#if notice}<p class="dim">{notice}</p>{/if}

    {#if selectedCount}
      <div class="bulkbar">
        <strong>{selectedCount} selected</strong>
        <button on:click={() => bulk('favorite')}>Favorite</button>
        <button on:click={() => bulk('unfavorite')}>Unfavorite</button>
        <button on:click={addTagBulk}>Add tag</button>
        <button on:click={removeTagBulk}>Remove tag</button>
        <button on:click={moveBulk}>Move</button>
        <span style="flex: 1"></span>
        <button class="danger" on:click={deleteBulk}>Delete</button>
        <button class="ghost" on:click={() => (selected = new Set())}>Clear</button>
      </div>
    {/if}

    <div class="row" style="justify-content: space-between; margin: 10px 0">
      <label class="row"><input type="checkbox" checked={allSelected} on:change={toggleAll} /> Select page</label>
      <span class="dim">{total} item(s)</span>
      <span style="flex: 1"></span>
      <div class="pagination">
        <button on:click={() => goPage(pageNo - 1)} disabled={pageNo === 0}>Previous</button>
        <span class="dim">{pageNo + 1} / {totalPages}</span>
        <button on:click={() => goPage(pageNo + 1)} disabled={pageNo + 1 >= totalPages}>Next</button>
        <select bind:value={pageSize} on:change={applyFilters} aria-label="Page size">
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </div>
    </div>

    {#if items.length}
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th></th>
              <th>Name</th>
              <th>Type</th>
              <th>Folder</th>
              <th>Tags</th>
              <th>Updated</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each visibleItems as item (item.id)}
              <tr class:selected-row={selected.has(item.id)}>
                <td><input type="checkbox" checked={selected.has(item.id)} on:change={() => toggleSelect(item.id)} /></td>
                <td>
                  <div class="row tight">
                    <button
                      class:on={item.favorite}
                      class="star"
                      title="Favorite"
                      aria-label="Toggle favorite"
                      on:click={() => toggleFavorite(item)}
                    >{item.favorite ? '★' : '☆'}</button>
                    <a class="item-name" href={`/items/${item.id}`}>{item.name}</a>
                    {#if childCount[item.id]}<span class="chip" title="Linked children">⛓ {childCount[item.id]}</span>{/if}
                    {#if item.deleted}<span class="badge">deleted</span>{/if}
                  </div>
                  {#if itemSub(item)}<div class="item-sub">{itemSub(item)}</div>{/if}
                </td>
                <td><span class={`badge ${item.type}`}>{item.type.replaceAll('_', ' ')}</span></td>
                <td class="dim">{item.folder || '—'}</td>
                <td class="dim">{item.tags?.length ? item.tags.join(', ') : '—'}</td>
                <td class="dim">{fmtTime(item.updated_ms)}</td>
                <td class="cell-actions"><a class="chip" href={`/items/${item.id}`}>Open</a></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty">
        <strong>No items match this view.</strong>
        <span>Try clearing filters or add a new item.</span>
        <div class="row"><a class="badge" href="/add">+ Add item</a><button class="ghost" on:click={clearFilters}>Clear filters</button></div>
      </div>
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
