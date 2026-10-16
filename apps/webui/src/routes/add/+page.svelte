<script>
  import { api } from '$lib/api.js';
  import { goto } from '$app/navigation';
  let item_type = 'login';
  let name = '';
  let folder = '';
  let rows = [{ k: 'username', v: '' }];
  let error = '';

  function addRow() {
    rows = [...rows, { k: '', v: '' }];
  }
  async function submit() {
    error = '';
    try {
      const fields = {};
      for (const r of rows) if (r.k) fields[r.k] = r.v;
      const res = await api.create({ type: item_type, name, folder, fields });
      goto(`/items/${res.id}`);
    } catch (e) {
      error = e.message;
    }
  }
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
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
  {#each rows as row}
    <div class="row">
      <input bind:value={row.k} placeholder="field" />
      <input bind:value={row.v} placeholder="value" style="flex: 1" />
    </div>
  {/each}
  <div class="row" style="margin-top: 8px">
    <button on:click={addRow}>Field</button>
    <button class="primary" on:click={submit}>Save</button>
  </div>
</main>
