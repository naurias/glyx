<script>
  import { api } from '$lib/api.js';
  import { renderMarkdown } from '$lib/markdown.js';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  let item = null;
  let reveal = false;
  let error = '';
  let code = '';
  let rendered = '';
  let editing = false;
  let bodyText = '';
  $: id = $page.params.id;

  async function load() {
    try {
      item = await api.show(id, reveal);
      code = '';
      if (item.type === 'note') {
        rendered = (await api.rendered(id, reveal)).body;
        bodyText = item.fields.body ?? '';
      }
    } catch (e) {
      error = e.message;
    }
  }
  onMount(load);
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
  async function save() {
    error = '';
    try {
      await api.edit(id, { fields: { body: bodyText } });
      editing = false;
      await load();
    } catch (e) {
      error = e.message;
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
</nav>
<main>
  {#if error}<p style="color: var(--danger)">{error}</p>{/if}
  {#if item}
    <h2>{item.name} <span class="dim">[{item.type}]</span></h2>
    <p class="dim">{item.id} · rev {item.rev}{item.folder ? ` · ${item.folder}` : ''}</p>
    {#if item.type === 'note'}
      {#if editing}
        <label>Note (markdown; reference secrets as glyx-&lt;id&gt;/&lt;field&gt; inside double braces)
          <textarea bind:value={bodyText} rows="14"></textarea>
        </label>
        <div class="row">
          <button class="primary" on:click={save}>Save</button>
          <button on:click={() => (editing = false)}>Cancel</button>
        </div>
      {:else}
        <div class="card note">{@html renderedHtml}</div>
        <div class="row">
          <button on:click={() => (editing = true)}>Edit</button>
          <button on:click={toggle}>{reveal ? 'Mask secrets' : 'Reveal secrets'}</button>
          <button class="danger" on:click={remove}>Delete</button>
        </div>
      {/if}
    {:else}
      {#each Object.entries(item.fields) as [k, v]}
        <div class="card row"><strong>{k}</strong><span>{v}</span></div>
      {/each}
      <div class="row">
        <button on:click={toggle}>{reveal ? 'Mask' : 'Reveal'}</button>
        {#if item.type === 'totp'}<button on:click={totp}>TOTP code</button>{/if}
        <button class="danger" on:click={remove}>Delete</button>
      </div>
      {#if code}<p>Code: <strong>{code}</strong></p>{/if}
    {/if}
  {/if}
</main>
