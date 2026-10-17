<script>
  import { api } from '$lib/api.js';
  import { renderMarkdown } from '$lib/markdown.js';
  import { goto } from '$app/navigation';
  let item_type = 'login';
  let name = '';
  let folder = '';
  let rows = [{ k: 'username', v: '' }];
  let body = '';
  let error = '';

  function addRow() {
    rows = [...rows, { k: '', v: '' }];
  }
  async function submit() {
    error = '';
    try {
      const fields = {};
      if (item_type === 'note') {
        fields.body = body;
      } else {
        for (const r of rows) if (r.k) fields[r.k] = r.v;
      }
      const res = await api.create({ type: item_type, name, folder, fields });
      goto(`/items/${res.id}`);
    } catch (e) {
      error = e.message;
    }
  }
  $: bodyPreview = renderMarkdown(body);
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
  <a href="/exports">Exports</a>
  <a href="/settings">Settings</a>
</nav>
<main>
  <h2>Add item</h2>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  <label>Type
    <select bind:value={item_type}>
      {#each ['login', 'passkey', 'totp', 'identity', 'card', 'note', 'file', 'ssh_key', 'generic_key'] as t}
        <option value={t}>{t}</option>
      {/each}
    </select>
  </label>
  <label>Name<input bind:value={name} /></label>
  <label>Folder<input bind:value={folder} /></label>
  {#if item_type === 'note'}
    <label>Note (markdown)
      <textarea bind:value={body} rows="12"></textarea>
    </label>
    <div class="card note">{@html bodyPreview}</div>
  {:else}
    {#each rows as row}
      <div class="row">
        <input bind:value={row.k} placeholder="field" />
        <input bind:value={row.v} placeholder="value" style="flex: 1" />
      </div>
    {/each}
    <div class="row" style="margin-top: 8px">
      <button on:click={addRow}>Field</button>
    </div>
  {/if}
  <div class="row" style="margin-top: 8px">
    <button class="primary" on:click={submit}>Save</button>
  </div>
</main>
