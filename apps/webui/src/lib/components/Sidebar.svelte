<script>
  import { page } from '$app/stores';

  export let vaultLabel = '';
  export let open = false;
  export let onclose = () => {};
  export let onlock = () => {};

  const groups = [
    {
      label: 'Vault',
      links: [
        { href: '/items', label: 'Items', icon: '▤' },
        { href: '/items?favorite=1', label: 'Favorites', icon: '★' },
        { href: '/items?recents=1', label: 'Recents', icon: '◷' },
        { href: '/passkeys', label: 'Passkeys', icon: '⚿' }
      ]
    },
    {
      label: 'Integrations',
      links: [
        { href: '/files', label: 'Files & Injection', icon: '▣' },
        { href: '/conflicts', label: 'Conflicts', icon: '⇄' }
      ]
    },
    {
      label: 'Security',
      links: [
        { href: '/health', label: 'Health', icon: '♥' },
        { href: '/devices', label: 'Devices', icon: '▢' },
        { href: '/audit', label: 'Audit', icon: '≡' }
      ]
    },
    {
      label: 'Tools',
      links: [
        { href: '/generator', label: 'Generator', icon: '✧' },
        { href: '/settings', label: 'Settings', icon: '⚙' },
        { href: '/onboarding', label: 'Vaults', icon: '⌂' }
      ]
    }
  ];

  function active(href) {
    const path = $page.url.pathname;
    const base = href.split('?')[0];
    if (base === '/items') {
      const fav = $page.url.searchParams.get('favorite');
      const rec = $page.url.searchParams.get('recents');
      if (href.includes('favorite=1')) return path === '/items' && fav === '1';
      if (href.includes('recents=1')) return path === '/items' && rec === '1';
      return path === '/items' && fav !== '1' && rec !== '1';
    }
    return path === base || path.startsWith(`${base}/`);
  }
</script>

<svelte:window on:keydown={(e) => e.key === 'Escape' && open && onclose()} />

<aside class:open class="app-sidebar" aria-label="Main navigation">
  <div class="brand">
    <div class="brand-mark">g</div>
    <div>
      <div class="brand-name">glyx</div>
      <div class="brand-sub">local-first vault</div>
    </div>
  </div>

  {#each groups as group}
    <div class="sidebar-section">
      <div class="sidebar-label">{group.label}</div>
      {#each group.links as link}
        <a
          class:active={active(link.href)}
          class="sidebar-link"
          href={link.href}
          on:click={onclose}
        >
          <span class="sidebar-icon" aria-hidden="true">{link.icon}</span>
          <span>{link.label}</span>
        </a>
      {/each}
    </div>
  {/each}

  <div class="sidebar-footer">
    {#if vaultLabel}
      <div class="vault-chip" title={vaultLabel}>
        <span class="vault-dot"></span>
        <span>{vaultLabel}</span>
      </div>
    {/if}
    <button class="ghost" on:click={onlock}>Lock vault</button>
  </div>
</aside>
