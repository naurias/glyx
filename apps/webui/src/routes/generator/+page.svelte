<script>
  import { api } from '$lib/api.js';
  let length = 24;
  let lowercase = true;
  let uppercase = true;
  let digits = true;
  let symbols = true;
  let excludeAmbiguous = true;
  let password = '';
  let entropy = 0;
  let error = '';
  let copied = false;

  async function generate() {
    error = '';
    copied = false;
    try {
      const result = await api.generate({
        length: Number(length),
        lowercase,
        uppercase,
        digits,
        symbols,
        exclude_ambiguous: excludeAmbiguous
      });
      password = result.password;
      entropy = result.entropy_bits;
    } catch (e) {
      error = e.message;
    }
  }

  async function copy() {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    copied = true;
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/devices">Devices</a>
  <a href="/health">Health</a>
  <a href="/audit">Audit</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Password generator</h2>
  <label>Length <input type="number" min="1" max="128" bind:value={length} /></label>
  <div class="row" style="flex-wrap: wrap">
    <label class="row"><input type="checkbox" bind:checked={lowercase} /> lowercase</label>
    <label class="row"><input type="checkbox" bind:checked={uppercase} /> uppercase</label>
    <label class="row"><input type="checkbox" bind:checked={digits} /> digits</label>
    <label class="row"><input type="checkbox" bind:checked={symbols} /> symbols</label>
    <label class="row"><input type="checkbox" bind:checked={excludeAmbiguous} /> exclude ambiguous</label>
  </div>
  <div class="row">
    <button class="primary" on:click={generate}>Generate</button>
    {#if password}<button on:click={copy}>{copied ? 'Copied' : 'Copy'}</button>{/if}
  </div>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if password}
    <div class="card">
      <code style="word-break: break-all">{password}</code>
      <p class="dim">Estimated entropy: {entropy.toFixed(1)} bits</p>
    </div>
  {/if}
</main>
