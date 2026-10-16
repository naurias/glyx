<script>
  import { api, configure, configured } from '$lib/api.js';
  import { goto } from '$app/navigation';
  let url = 'http://127.0.0.1:8080';
  let token = '';
  let password = '';
  let keyfile = '';
  let pin = '';
  let error = '';
  let mode = 'password';

  async function connect() {
    error = '';
    try {
      configure(url, token);
      const st = await api.status();
      if (st.locked) {
        if (mode === 'pin') await api.unlockPin(pin);
        else await api.unlock(password, keyfile);
      }
      password = '';
      pin = '';
      goto('/items');
    } catch (e) {
      error = e.message;
    }
  }
</script>

<main>
  <h1>glyx</h1>
  <p class="dim">Local-first password manager. The daemon holds your vault; this page keeps secrets in memory only.</p>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  <label>Daemon URL<input bind:value={url} placeholder="http://127.0.0.1:PORT" /></label>
  <label>Token<input bind:value={token} placeholder="from daemon-*.json" /></label>
  <div class="row">
    <button class:selected={mode === 'password'} on:click={() => (mode = 'password')}>Password</button>
    <button class:selected={mode === 'pin'} on:click={() => (mode = 'pin')}>PIN</button>
  </div>
  {#if mode === 'password'}
    <label>Password<input type="password" bind:value={password} /></label>
    <label>Keyfile path<input bind:value={keyfile} placeholder="/path/to/keyfile" /></label>
  {:else}
    <label>PIN<input type="password" bind:value={pin} /></label>
  {/if}
  <div class="row"><button class="primary" on:click={connect}>Unlock</button></div>
  {#if !configured()}<p class="dim">Find the port and token in your runtime dir: <code>daemon-&lt;vault&gt;.json</code> (run <code>glyx daemon start</code>).</p>{/if}
</main>

<style>
  .selected { border-color: var(--accent); }
</style>
