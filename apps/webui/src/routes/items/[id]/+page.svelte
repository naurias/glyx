<script>
  import { api } from '$lib/api.js';
  import { renderMarkdown } from '$lib/markdown.js';
  import ItemForm from '$lib/ItemForm.svelte';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  let item = null;
  let templates = [];
  let reveal = false;
  let error = '';
  let notice = '';
  let code = '';
  let rendered = '';
  let editing = false;
  let editValues = {};
  let busy = false;
  $: id = $page.params.id;

  async function load() {
    try {
      item = await api.show(id, reveal);
      code = '';
      if (item.type === 'note') {
        rendered = (await api.rendered(id, reveal)).body;
      }
    } catch (e) {
      error = e.message;
    }
  }

  onMount(async () => {
    try {
      templates = await api.templates();
    } catch (e) {
      error = e.message;
    }
    await load();
  });

  async function toggle() {
    reveal = !reveal;
    await load();
  }

  async function totp() {
    try {
      code = (await api.totp(id)).code;
    } catch (e) {
      error = e.message;
    }
  }

  async function copy(field) {
    error = '';
    notice = '';
    try {
      await api.fill(id, field);
      notice = `${field} copied (clears in 15s)`;
    } catch (e) {
      error = e.message;
    }
  }

  async function startEdit() {
    error = '';
    try {
      const full = await api.show(id, true);
      editValues = { ...full.fields };
      editing = true;
    } catch (e) {
      error = e.message;
    }
  }

  async function save(payload) {
    error = '';
    busy = true;
    try {
      await api.edit(id, {
        rename: payload.name,
        folder: payload.folder,
        tags: payload.tags,
        fields: payload.fields
      });
      editing = false;
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function remove() {
    if (!confirm('Delete this item (tombstone kept for sync)?')) return;
    await api.remove(id);
    goto('/items');
  }

  $: renderedHtml = renderMarkdown(rendered);
</script>

<nav>
  <a href="/items">Items</a>
  <a href="/add">Add</a>
  <a href="/conflicts">Conflicts</a>
  <a href="/exports">Exports</a>
  <a href="/settings">Settings</a>
  <a href="/onboarding">Vaults</a>
  <span style="flex: 1"></span>
</nav>
<main>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if notice}<p class="dim">{notice}</p>{/if}
  {#if item}
    <h2>{item.name} <span class="dim">[{item.type}]</span></h2>
    <p class="dim">{item.id} · rev {item.rev}{item.folder ? ` · ${item.folder}` : ''}</p>
    {#if editing}
      <ItemForm
        {templates}
        item_type={item.type}
        name={item.name}
        folder={item.folder}
        values={editValues}
        tags={item.tags}
        lockType
        submitLabel="Save changes"
        {busy}
        onsubmit={save}
        oncancel={() => (editing = false)}
      />
    {:else if item.type === 'note'}
      <div class="card note">{@html renderedHtml}</div>
      <div class="row">
        <button on:click={startEdit}>Edit</button>
        <button on:click={toggle}>{reveal ? 'Mask secrets' : 'Reveal secrets'}</button>
        <button class="danger" on:click={remove}>Delete</button>
      </div>
    {:else}
      {#each Object.entries(item.fields) as [k, v]}
        <div class="card row">
          <strong>{k}</strong>
          <span style="flex: 1">{v}</span>
          <button on:click={() => copy(k)}>Copy</button>
        </div>
      {/each}
      <div class="row">
        <button on:click={startEdit}>Edit</button>
        <button on:click={toggle}>{reveal ? 'Mask' : 'Reveal'}</button>
        {#if item.type === 'totp'}<button on:click={totp}>TOTP code</button>{/if}
        <button class="danger" on:click={remove}>Delete</button>
      </div>
      {#if code}<p>Code: <strong>{code}</strong></p>{/if}
    {/if}
  {/if}
</main>
