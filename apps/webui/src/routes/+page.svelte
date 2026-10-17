<script>
  import { api, configure, configured, bootstrapDesktop } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let url = 'http://127.0.0.1:8080';
  let token = '';
  let password = '';
  let keyfile = '';
  let pin = '';
  let error = '';
  let mode = 'password';
  let desktop = false;
  let needsKeyfile = true;
  let vaultLabel = '';

  async function loadStatus() {
    const st = await api.status();
    if (!st.vault) {
      goto('/onboarding');
      return false;
    }
    needsKeyfile = st.vault.keyfile_required !== false;
    vaultLabel = st.vault.path;
    if (!st.locked) {
      goto('/items');
      return false;
    }
    return true;
  }

  onMount(async () => {
    desktop = bootstrapDesktop();
    if (desktop) {
      try {
        await loadStatus();
      } catch (e) {
        error = e.message;
      }
    }
  });

  async function connect() {
    error = '';
    if (!desktop) configure(url, token);
    try {
      const locked = await loadStatus();
      if (!locked) return;
      if (mode === 'pin') await api.unlockPin(pin);
      else await api.unlock(password, needsKeyfile && keyfile ? keyfile : undefined);
      password = '';
      pin = '';
      goto('/items');
    } catch (e) {
      error = e.message;
    }
  }

  function goOnboarding() {
    if (!desktop && (url || token)) configure(url, token);
    goto('/onboarding');
  }
</script>

<main>
  <h1>glyx</h1>
  <p class="dim">Local-first password manager. The daemon holds your vault; this page keeps secrets in memory only.</p>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if desktop}
    {#if vaultLabel}<p class="dim">Vault: <code>{vaultLabel}</code></p>{/if}
  {:else}
    <label>Daemon URL<input bind:value={url} placeholder="http://127.0.0.1:PORT" /></label>
    <label>Token<input bind:value={token} placeholder="from daemon-*.json" /></label>
  {/if}
  <div class="row">
    <button class:selected={mode === 'password'} on:click={() => (mode = 'password')}>Password</button>
    <button class:selected={mode === 'pin'} on:click={() => (mode = 'pin')}>PIN</button>
  </div>
  {#if mode === 'password'}
    <label>Password<input type="password" bind:value={password} /></label>
    {#if needsKeyfile}
      <label>Keyfile path<input bind:value={keyfile} placeholder="/path/to/keyfile" /></label>
    {/if}
  {:else}
    <label>PIN<input type="password" bind:value={pin} /></label>
  {/if}
  <div class="row">
    <button class="primary" on:click={connect}>Unlock</button>
    <button on:click={goOnboarding}>Vaults...</button>
  </div>
  {#if !desktop && !configured()}<p class="dim">Find the port and token in your runtime dir: <code>daemon-&lt;vault&gt;.json</code> (run <code>glyx daemon start</code>), or enter them to manage vaults.</p>{/if}
</main>

<style>
  .selected { border-color: var(--accent); }
</style>
