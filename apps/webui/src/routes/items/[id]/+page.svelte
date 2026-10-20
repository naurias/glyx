<script>
  import { api, downloadBlob } from '$lib/api.js';
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
  let fillTimeout = 15;
  let history = [];
  let historyOpen = false;
  let historyPreview = null;
  let historyPreviewFile = null;
  let historyReveal = false;
  let historyCompare = null;
  let attachInput = null;
  let uploading = false;
  $: id = $page.params.id;

  async function load() {
    try {
      item = await api.show(id, reveal);
      code = '';
      historyPreview = null;
      if (item.type === 'note') {
        rendered = (await api.rendered(id, reveal)).body;
      }
      history = (await api.history(id)).items || [];
    } catch (e) {
      error = e.message;
    }
  }

  function fmtTime(hlc) {
    return hlc && hlc.wall_ms ? new Date(hlc.wall_ms).toLocaleString() : '';
  }

  async function previewHistory(entry) {
    error = '';
    historyCompare = null;
    try {
      historyPreviewFile = entry.file;
      historyPreview = (await api.historyItem(id, entry.file, historyReveal)).item;
    } catch (e) {
      error = e.message;
    }
  }

  async function toggleHistoryReveal() {
    historyReveal = !historyReveal;
    if (historyPreview) {
      try {
        historyPreview = (await api.historyItem(id, historyPreviewFile, historyReveal)).item;
      } catch (e) {
        error = e.message;
      }
    }
  }

  async function compareHistory(entry) {
    error = '';
    try {
      historyCompare = { entry, ...(await api.historyCompare(id, entry.file)) };
    } catch (e) {
      error = e.message;
    }
  }

  async function uploadAttachment() {
    const file = attachInput?.files?.[0];
    if (!file) return;
    if (file.size > 25 * 1024 * 1024) {
      error = 'attachment exceeds the 25 MiB limit';
      return;
    }
    error = '';
    uploading = true;
    try {
      const { addr } = await api.uploadBlob(file);
      await api.edit(id, { fields: { blob: addr } });
      notice = 'attachment uploaded';
      await load();
      if (attachInput) attachInput.value = '';
    } catch (e) {
      error = e.message;
    } finally {
      uploading = false;
    }
  }

  async function downloadAttachment() {
    error = '';
    try {
      await downloadBlob(item.fields.blob);
    } catch (e) {
      error = e.message;
    }
  }

  async function removeAttachment() {
    if (!confirm('Remove the attachment? The encrypted blob is kept until GC.')) return;
    error = '';
    try {
      await api.edit(id, { delete_fields: ['blob'] });
      notice = 'attachment removed';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function restoreHistory(entry) {
    if (!confirm(`Restore revision ${entry.rev}? This creates a new revision.`)) return;
    error = '';
    notice = '';
    try {
      await api.restoreHistory(id, entry.file);
      notice = `restored revision ${entry.rev}`;
      await load();
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
      const timeout = Number(fillTimeout) || 15;
      await api.fill(id, field, timeout);
      notice = `${field} copied (clears in ${timeout}s)`;
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
        {#if item.type === 'totp' || item.fields.seed !== undefined}
          <button on:click={totp}>TOTP code</button>
        {/if}
        <label class="row">clipboard clear
          <input type="number" min="0" max="600" bind:value={fillTimeout} style="width: 5rem" />s
        </label>
        <button class="danger" on:click={remove}>Delete</button>
      </div>
      {#if code}<p>Code: <strong>{code}</strong></p>{/if}
    {/if}
    <div class="card">
      <div class="row">
        <strong>Attachment</strong>
        <span class="dim">encrypted · 25 MiB max</span>
        <span style="flex: 1"></span>
      </div>
      {#if item.fields.blob}
        <p class="dim">{item.fields.blob}</p>
        <div class="row">
          <button on:click={downloadAttachment}>Download</button>
          <button class="danger" on:click={removeAttachment}>Remove</button>
        </div>
      {:else}
        <div class="row">
          <input type="file" bind:this={attachInput} />
          <button on:click={uploadAttachment} disabled={uploading}>
            {uploading ? 'Uploading...' : 'Attach'}
          </button>
        </div>
      {/if}
    </div>
    <div class="card">
      <div class="row">
        <strong>History</strong>
        <span class="dim">({history.length})</span>
        <span style="flex: 1"></span>
        <button on:click={() => (historyOpen = !historyOpen)}>
          {historyOpen ? 'Hide' : 'Show'}
        </button>
      </div>
      {#if historyOpen}
        {#if !history.length}
          <p class="dim">No earlier revisions.</p>
        {/if}
        {#each history as entry (entry.file)}
          <div class="row">
            <span>rev {entry.rev} · {fmtTime(entry.hlc)}{entry.deleted ? ' [deleted]' : ''}</span>
            <span class="dim">{entry.file}</span>
            <span style="flex: 1"></span>
            <button on:click={() => previewHistory(entry)}>Preview</button>
            <button on:click={() => compareHistory(entry)}>Compare</button>
            <button on:click={() => restoreHistory(entry)}>Restore</button>
          </div>
        {/each}
        {#if historyPreview}
          <div class="card">
            <div class="row">
              <strong>{historyPreview.name}</strong>
              <span class="dim">rev {historyPreview.rev}</span>
              <span style="flex: 1"></span>
              <button on:click={toggleHistoryReveal}>
                {historyReveal ? 'Mask secrets' : 'Reveal secrets'}
              </button>
              <button on:click={() => (historyPreview = null)}>Close</button>
            </div>
            {#each Object.entries(historyPreview.fields) as [k, v]}
              <div class="row"><strong>{k}</strong><span>{v}</span></div>
            {/each}
          </div>
        {/if}
        {#if historyCompare}
          <div class="card">
            <div class="row">
              <strong>Changes vs rev {historyCompare.entry.rev}</strong>
              <span class="dim">current rev {historyCompare.current_rev}</span>
              <span style="flex: 1"></span>
              <button on:click={() => (historyCompare = null)}>Close</button>
            </div>
            {#if historyCompare.changed.length}
              <p>{historyCompare.changed.join(', ')}</p>
            {:else}
              <p class="dim">No differences.</p>
            {/if}
          </div>
        {/if}
      {/if}
    </div>
  {/if}
</main>
