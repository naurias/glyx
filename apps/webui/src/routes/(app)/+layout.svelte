<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { api, bootstrapDesktop, configured } from '$lib/api.js';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import TopBar from '$lib/components/TopBar.svelte';
  import Quick from '$lib/Quick.svelte';

  let vaultLabel = '';
  let ready = false;
  let sidebarOpen = false;
  let quick = false;

  async function ensure() {
    if (!bootstrapDesktop() && !configured()) {
      await goto('/');
      return;
    }
    try {
      const st = await api.status();
      if (!st.vault) {
        await goto('/onboarding');
        return;
      }
      if (st.locked) {
        await goto('/');
        return;
      }
      vaultLabel = st.vault.path || '';
      ready = true;
    } catch {
      await goto('/');
    }
  }

  async function lock() {
    try {
      await api.lock();
    } finally {
      await goto('/');
    }
  }

  onMount(() => {
    ensure();
    const open = () => (quick = true);
    const lockEvent = () => lock();
    const keys = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        lock();
      }
    };
    window.addEventListener('glyx-quick', open);
    window.addEventListener('glyx-lock', lockEvent);
    window.addEventListener('keydown', keys);
    return () => {
      window.removeEventListener('glyx-quick', open);
      window.removeEventListener('glyx-lock', lockEvent);
      window.removeEventListener('keydown', keys);
    };
  });
</script>

{#if ready}
  <div class="app-shell">
    <Sidebar
      {vaultLabel}
      open={sidebarOpen}
      onclose={() => (sidebarOpen = false)}
      onlock={lock}
    />
    {#if sidebarOpen}
      <div class="sidebar-backdrop show" on:click={() => (sidebarOpen = false)} role="presentation"></div>
    {/if}
    <div class="app-main">
      <TopBar
        {vaultLabel}
        onmenu={() => (sidebarOpen = true)}
        onlock={lock}
      />
      <main class="app-content">
        <slot />
      </main>
    </div>
  </div>
{:else}
  <div class="auth-shell"><p class="dim">Loading vault...</p></div>
{/if}

{#if quick}<Quick onclose={() => (quick = false)} />{/if}
