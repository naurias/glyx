<script>
  import {
    api,
    configure,
    configured,
    bootstrapDesktop,
    bootstrapError,
    retryDesktopBootstrap
  } from '$lib/api.js';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let url = 'http://127.0.0.1:8080';
  let token = '';
  let password = '';
  let keyfile = '';
  let pin = '';
  let newPin = '';
  let setPin = false;
  let advanced = false;
  let ttlMin = '';
  let materialize = 'default';
  let error = '';
  let mode = 'password';
  let desktop = false;
  let needsKeyfile = true;
  let vaultLabel = '';
  let booting = false;
  let bootError = '';

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

  async function ensureDesktop() {
    desktop = bootstrapDesktop();
    bootError = bootstrapError();
    if (!configured() && window.__TAURI__?.core?.invoke) {
      booting = true;
      const ok = await retryDesktopBootstrap();
      booting = false;
      desktop = ok;
      bootError = ok ? '' : bootstrapError();
    }
    return configured();
  }

  async function retry() {
    error = '';
    bootError = '';
    booting = true;
    const ok = await retryDesktopBootstrap();
    booting = false;
    desktop = ok;
    if (!ok) {
      bootError = bootstrapError() || 'daemon did not start';
      return;
    }
    try {
      await loadStatus();
    } catch (e) {
      bootError = e.message;
    }
  }

  onMount(async () => {
    if (await ensureDesktop()) {
      try {
        await loadStatus();
      } catch (e) {
        bootError = e.message;
      }
    }
  });

  async function connect() {
    error = '';
    if (!desktop) configure(url, token);
    try {
      const locked = await loadStatus();
      if (!locked) return;
      const options = {};
      if (ttlMin) options.ttl_min = Number(ttlMin);
      if (materialize !== 'default') options.materialize = materialize === 'yes';
      if (mode === 'pin') await api.unlockPin(pin, options);
      else
        await api.unlock(
          password,
          needsKeyfile && keyfile ? keyfile : undefined,
          setPin && newPin ? newPin : undefined,
          options
        );
      password = '';
      pin = '';
      newPin = '';
      ttlMin = '';
      materialize = 'default';
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
  {#if booting}
    <p class="dim">Starting the glyx daemon...</p>
  {:else if bootError}
    <div class="card">
      <p style="color: var(--danger)">Could not start the glyx daemon.</p>
      <p class="dim">{bootError}</p>
      <div class="row">
        <button class="primary" on:click={retry}>Retry</button>
        <button on:click={goOnboarding}>Vaults...</button>
      </div>
    </div>
  {:else if desktop}
    {#if vaultLabel}<p class="dim">Vault: <code>{vaultLabel}</code></p>{/if}
  {:else}
    <label>Daemon URL<input bind:value={url} placeholder="http://127.0.0.1:PORT" /></label>
    <label>Token<input bind:value={token} placeholder="from daemon-*.json" /></label>
  {/if}
  {#if !booting && !bootError}
  <div class="row">
    <button class:selected={mode === 'password'} on:click={() => (mode = 'password')}>Password</button>
    <button class:selected={mode === 'pin'} on:click={() => (mode = 'pin')}>PIN</button>
  </div>
  {#if mode === 'password'}
    <label>Password<input type="password" bind:value={password} /></label>
    {#if needsKeyfile}
      <label>Keyfile path<input bind:value={keyfile} placeholder="/path/to/keyfile" /></label>
    {/if}
    <div class="row">
      <button class:selected={setPin} on:click={() => (setPin = !setPin)}>Also set a PIN</button>
    </div>
    {#if setPin}
      <label>New PIN (min 4)<input type="password" bind:value={newPin} /></label>
    {/if}
  {:else}
    <label>PIN<input type="password" bind:value={pin} /></label>
  {/if}
  <div class="row">
    <button class:selected={advanced} on:click={() => (advanced = !advanced)}>Advanced</button>
  </div>
  {#if advanced}
    <div class="card">
      {#if mode === 'password'}
        <label>Session TTL minutes (optional)
          <input type="number" min="1" max="480" bind:value={ttlMin} placeholder="default" />
        </label>
      {/if}
      <label>Materialize tracked exports
        <select bind:value={materialize}>
          <option value="default">use setting</option>
          <option value="yes">yes</option>
          <option value="no">no</option>
        </select>
      </label>
    </div>
  {/if}
  <div class="row">
    <button class="primary" on:click={connect}>Unlock</button>
    <button on:click={goOnboarding}>Vaults...</button>
  </div>
  {#if !desktop && !configured()}<p class="dim">Find the port and token in your runtime dir: <code>daemon-&lt;vault&gt;.json</code> (run <code>glyx daemon start</code>), or enter them to manage vaults.</p>{/if}
  {/if}
</main>

<style>
  .selected { border-color: var(--accent); }
</style>
