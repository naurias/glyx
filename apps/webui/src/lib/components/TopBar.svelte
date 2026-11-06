<script>
  import { goto } from '$app/navigation';

  export let vaultLabel = '';
  export let onmenu = () => {};
  export let onlock = () => {};

  let q = '';
  let searchInput;

  function submit(e) {
    e.preventDefault();
    const value = q.trim();
    goto(value ? `/items?q=${encodeURIComponent(value)}` : '/items');
  }

  function focusSearch() {
    searchInput?.focus();
    searchInput?.select();
  }
</script>

<svelte:window
  on:keydown={(e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      focusSearch();
    }
  }}
/>

<header class="app-topbar">
  <button class="ghost mobile-toggle" on:click={onmenu} aria-label="Open navigation">☰</button>
  <form class="topbar-search" on:submit={submit} role="search">
    <input
      bind:this={searchInput}
      bind:value={q}
      type="search"
      placeholder="Search items, folders, tags..."
      aria-label="Search items"
    />
  </form>
  <span class="topbar-spacer"></span>
  {#if vaultLabel}
    <span class="vault-chip" title={vaultLabel}>
      <span class="vault-dot"></span>
      <span>{vaultLabel}</span>
    </span>
  {/if}
  <a class="badge" href="/add">+ Add item</a>
  <button class="ghost" on:click={onlock}>Lock</button>
</header>
