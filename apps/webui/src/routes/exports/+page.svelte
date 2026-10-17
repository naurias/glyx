<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let data = { exports: [], injects: [] };
  let tamper = [];
  let error = '';
  let target = '';
  let form = 'encrypted-pointer';
  let merging = null;
  let hunks = [];
  let picks = {};

  async function load() {
    try {
      data = await api.exports();
      tamper = await api.tamper();
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
  async function recall(t) {
    try {
      await api.recall(t);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function enforce(force) {
    try {
      await api.enforce(force);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function track() {
    try {
      await api.trackInject(target, form);
      target = '';
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function resolve(t, action) {
    try {
      await api.resolveTamper(t, action);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function preview(t) {
    try {
      const res = await api.mergePreview(t);
      merging = t;
      hunks = res.hunks || [];
      picks = {};
    } catch (e) {
      error = e.message;
    }
  }
  async function applyMerge() {
    try {
      await api.mergeApply(merging, picks);
      merging = null;
      hunks = [];
      await load();
    } catch (e) {
      error = e.message;
    }
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
  <a href="/exports">Exports</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Exports</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if tamper.length}
    <div class="card">
      <strong>Tamper detected</strong>
      {#each tamper as t}
        <div class="row"><span>{t}</span></div>
        <div class="row">
          <button on:click={() => enforce(true)}>Force re-materialize</button>
        </div>
      {/each}
    </div>
  {/if}
  {#if merging}
    <div class="card">
      <strong>Merging {merging}</strong>
      {#each hunks as h, i}
        {#if h.kind === 'conflict'}
          <div class="card">
            <div class="dim">hunk {i}{h.secret ? ' [secret]' : ''}</div>
            <div><strong>theirs</strong><pre>{h.theirs.join('\n')}</pre></div>
            <div><strong>ours</strong><pre>{h.ours.join('\n')}</pre></div>
            <div class="row">
              <button on:click={() => (picks[i] = 'theirs')}>Theirs{picks[i] === 'theirs' ? ' ✓' : ''}</button>
              <button on:click={() => (picks[i] = 'ours')}>Ours{picks[i] === 'ours' ? ' ✓' : ''}</button>
            </div>
          </div>
        {/if}
      {/each}
      <div class="row">
        <button class="primary" on:click={applyMerge}>Apply merge</button>
        <button on:click={() => (merging = null)}>Cancel</button>
      </div>
    </div>
  {/if}
  <h3>Files</h3>
  {#each data.exports as e}
    <div class="card row">
      <span>{e.target}</span>
      <span class="dim">{e.kind}{e.keep ? ' · keep' : ''}</span>
      <span style="flex: 1"></span>
      <button class="danger" on:click={() => recall(e.target)}>Recall</button>
    </div>
  {/each}
  <h3>Injected files</h3>
  {#each data.injects as i}
    <div class="card row">
      <span>{i.target}</span>
      <span class="dim">{i.form}</span>
      <span style="flex: 1"></span>
      <button on:click={() => preview(i.target)}>Merge</button>
      <button class="danger" on:click={() => recall(i.target)}>Recall</button>
    </div>
  {/each}
  {#if !data.exports.length && !data.injects.length}
    <p class="dim">Nothing tracked. Register from the CLI: <code>glyx export add</code>, <code>glyx inject add</code>.</p>
  {/if}
  <h3>Track a file for injection</h3>
  <div class="row">
    <input bind:value={target} placeholder="/path/to/.env" style="flex: 1" />
    <select bind:value={form}>
      <option value="encrypted-pointer">encrypted-pointer</option>
      <option value="masked">masked</option>
      <option value="ref">ref</option>
    </select>
    <button class="primary" on:click={track}>Track</button>
  </div>
  <div class="row" style="margin-top: 12px">
    <button on:click={() => enforce(false)}>Enforce now</button>
  </div>
</main>
