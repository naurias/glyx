<script>
  export let type = '';
  export let folder = '';
  export let tag = '';
  export let favoritesOnly = false;
  export let recentsOnly = false;
  export let library = { tags: {}, folders: {} };
  export let recents = [];
  export let onselect = () => {};

  const types = [
    ['login', 'Logins'],
    ['passkey', 'Passkeys'],
    ['totp', 'TOTP'],
    ['identity', 'Identities'],
    ['card', 'Cards'],
    ['note', 'Notes'],
    ['file', 'Files'],
    ['ssh_key', 'SSH keys'],
    ['generic_key', 'Generic keys']
  ];

  function pick(next) {
    onselect({
      type: next.type ?? '',
      folder: next.folder ?? '',
      tag: next.tag ?? '',
      favoritesOnly: next.favoritesOnly ?? false,
      recentsOnly: next.recentsOnly ?? false
    });
  }
</script>

<div class="filter-panel">
  <div class="filter-group">
    <button
      class:active={!type && !folder && !tag && !favoritesOnly && !recentsOnly}
      class="filter-item"
      on:click={() => pick({})}
    >
      <span>▤</span><span>All items</span>
    </button>
    <button
      class:active={favoritesOnly}
      class="filter-item"
      on:click={() => pick({ favoritesOnly: true })}
    >
      <span>★</span><span>Favorites</span>
    </button>
    <button
      class:active={recentsOnly}
      class="filter-item"
      on:click={() => pick({ recentsOnly: true })}
    >
      <span>◷</span><span>Recents</span>
      {#if recents.length}<span class="filter-count">{recents.length}</span>{/if}
    </button>
  </div>

  <div class="filter-group">
    <div class="filter-title">Types</div>
    {#each types as [value, label]}
      <button
        class:active={type === value}
        class="filter-item"
        on:click={() => pick({ type: type === value ? '' : value })}
      >
        <span>{label}</span>
      </button>
    {/each}
  </div>

  {#if Object.keys(library.folders || {}).length}
    <div class="filter-group">
      <div class="filter-title">Folders</div>
      {#each Object.entries(library.folders) as [name, count]}
        <button
          class:active={folder === name}
          class="filter-item"
          on:click={() => pick({ folder: folder === name ? '' : name })}
        >
          <span>▸</span><span>{name}</span><span class="filter-count">{count}</span>
        </button>
      {/each}
    </div>
  {/if}

  {#if Object.keys(library.tags || {}).length}
    <div class="filter-group">
      <div class="filter-title">Tags</div>
      {#each Object.entries(library.tags) as [name, count]}
        <button
          class:active={tag === name}
          class="filter-item"
          on:click={() => pick({ tag: tag === name ? '' : name })}
        >
          <span>#</span><span>{name}</span><span class="filter-count">{count}</span>
        </button>
      {/each}
    </div>
  {/if}

  <div class="filter-group">
    <div class="filter-title">Manage</div>
    <a class="filter-item" href="/library"><span>⚙</span><span>Tags & folders</span></a>
    <a class="filter-item" href="/items/duplicates"><span>⧉</span><span>Duplicates</span></a>
  </div>
</div>
