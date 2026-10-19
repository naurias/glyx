<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  let data = { exports: [], injects: [], roots: [] };
  let tamper = [];
  let error = '';
  let notice = '';
  let target = '';
  let form = 'encrypted-pointer';
  let glob = '*.md';
  let exp = {
    target: '',
    kind: 'field',
    item: '',
    field: 'password',
    blob: '',
    ssh: '',
    keep: false,
    perm: '600'
  };
  let ssh = { item: '', to: '', perm: '600' };
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
      await api.trackInject(target, form, glob);
      target = '';
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function scan() {
    try {
      await api.scanInjects();
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function tUnlock(t) {
    try {
      await api.targetUnlock(t);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function tLock(t) {
    try {
      await api.targetLock(t);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function tMove(t) {
    const nu = prompt(`New path for ${t}`, t);
    if (!nu || nu === t) return;
    try {
      await api.targetMove(t, nu);
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function addExport() {
    error = '';
    try {
      const body = {
        target: exp.target,
        kind: exp.kind,
        keep: exp.keep,
        perm: parseInt(exp.perm || '600', 8)
      };
      if (exp.kind === 'field') {
        body.item = exp.item;
        body.field = exp.field;
      } else if (exp.kind === 'blob') {
        body.blob = exp.blob;
      } else {
        body.ssh = exp.ssh;
      }
      await api.addExport(body);
      exp.target = '';
      await load();
    } catch (e) {
      error = e.message;
    }
  }
  async function exportSsh() {
    error = '';
    notice = '';
    try {
      const body = { item: ssh.item, perm: parseInt(ssh.perm || '600', 8) };
      if (ssh.to) body.to = ssh.to;
      const result = await api.sshExport(body);
      notice = `ssh key written to ${result.target}`;
      ssh.item = '';
      ssh.to = '';
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
  {#if notice}<p class="dim">{notice}</p>{/if}
  {#if tamper.length}
    <div class="card">
      <strong>Tamper detected</strong>
      {#each tamper as t}
        {@const tgt = typeof t === 'string' ? t : t.target || ''}
        <div class="row">
          <span>{typeof t === 'string' ? t : `${t.target} (${t.kind})`}</span>
        </div>
        <div class="row">
          <button on:click={() => enforce(true)}>Force re-materialize</button>
          {#if tgt}
            <button class="danger" on:click={() => resolve(tgt, 'keep')}>Keep (stop tracking)</button>
          {/if}
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
  <h3>Tracked folders</h3>
  {#each data.roots as r}
    <div class="card row">
      <span>{r.root}</span>
      <span class="dim">{r.glob} · {r.form}</span>
      <span style="flex: 1"></span>
      <button on:click={() => tUnlock(r.root)}>Unlock</button>
      <button on:click={() => tLock(r.root)}>Lock</button>
      <button on:click={() => tMove(r.root)}>Move</button>
      <button class="danger" on:click={() => recall(r.root)}>Forget</button>
    </div>
  {/each}
  {#if data.roots.length}
    <div class="row"><button on:click={scan}>Scan folders</button></div>
  {/if}
  <h3>Files</h3>
  {#each data.exports as e}
    <div class="card row">
      <span>{e.target}</span>
      <span class="dim">{e.kind}{e.keep ? ' · keep' : ''}</span>
      <span style="flex: 1"></span>
      <button on:click={() => tUnlock(e.target)}>Unlock</button>
      <button on:click={() => tLock(e.target)}>Lock</button>
      <button on:click={() => tMove(e.target)}>Move</button>
      <button class="danger" on:click={() => recall(e.target)}>Recall</button>
    </div>
  {/each}
  <h3>Injected files</h3>
  {#each data.injects as i}
    <div class="card row">
      <span>{i.target}</span>
      <span class="dim">{i.form}</span>
      <span style="flex: 1"></span>
      <button on:click={() => tUnlock(i.target)}>Unlock</button>
      <button on:click={() => tLock(i.target)}>Lock</button>
      <button on:click={() => tMove(i.target)}>Move</button>
      <button on:click={() => preview(i.target)}>Merge</button>
      <button class="danger" on:click={() => recall(i.target)}>Recall</button>
    </div>
  {/each}
  {#if !data.exports.length && !data.injects.length && !data.roots.length}
    <p class="dim">Nothing tracked. Register from the CLI: <code>glyx export add</code>, <code>glyx inject add</code>.</p>
  {/if}
  <h3>Track a file or folder for injection</h3>
  <div class="row">
    <input bind:value={target} placeholder="/path/to/.env or /path/to/folder" style="flex: 1" />
    <input bind:value={glob} placeholder="*.md" />
    <select bind:value={form}>
      <option value="encrypted-pointer">encrypted-pointer</option>
      <option value="masked">masked</option>
      <option value="ref">ref</option>
    </select>
    <button class="primary" on:click={track}>Track</button>
  </div>
  <h3>Add a full-file export</h3>
  <div class="row">
    <input bind:value={exp.target} placeholder="/path/to/target" style="flex: 1" />
    <select bind:value={exp.kind}>
      <option value="field">field</option>
      <option value="blob">blob</option>
      <option value="ssh">ssh</option>
    </select>
    {#if exp.kind === 'field'}
      <input bind:value={exp.item} placeholder="item" />
      <input bind:value={exp.field} placeholder="field" />
    {:else if exp.kind === 'blob'}
      <input bind:value={exp.blob} placeholder="blob address" />
    {:else}
      <input bind:value={exp.ssh} placeholder="ssh key item" />
    {/if}
    <label class="row"><input type="checkbox" bind:checked={exp.keep} /> keep on lock</label>
    <label class="row">perm <input bind:value={exp.perm} style="width: 4.5rem" /></label>
    <button class="primary" on:click={addExport}>Add export</button>
  </div>
  <h3>Export an SSH key</h3>
  <div class="row">
    <input bind:value={ssh.item} placeholder="ssh key item" />
    <input bind:value={ssh.to} placeholder="target path (default ~/.ssh/glyx_<name>)" style="flex: 1" />
    <label class="row">perm <input bind:value={ssh.perm} style="width: 4.5rem" /></label>
    <button class="primary" on:click={exportSsh} disabled={!ssh.item}>Export key</button>
  </div>
  <div class="row" style="margin-top: 12px">
    <button on:click={() => enforce(false)}>Enforce now</button>
  </div>
</main>
