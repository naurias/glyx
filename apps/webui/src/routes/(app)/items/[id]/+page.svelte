<script>
  import { api, downloadBlob } from '$lib/api.js';
  import { renderMarkdown } from '$lib/markdown.js';
  import ItemForm from '$lib/ItemForm.svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import PromptDialog from '$lib/components/PromptDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';
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
  let related = { children: [], parent: null, used_by: { injects: [], exports: [] } };
  let allItems = [];
  let linkChoice = '';
  let history = [];
  let historyOpen = false;
  let historyPreview = null;
  let historyPreviewFile = null;
  let historyReveal = false;
  let historyCompare = null;
  let attachInput = null;
  let uploading = false;

  let confirmOpen = false;
  let confirmTitle = '';
  let confirmMessage = '';
  let confirmLabel = 'Confirm';
  let confirmDanger = true;
  let confirmAction = () => {};

  let promptOpen = false;
  let promptTitle = '';
  let promptLabel = '';
  let promptValue = '';
  let promptConfirmLabel = 'Save';
  let promptAction = () => {};

  $: id = $page.params.id;
  $: fields = item?.fields || {};
  $: fieldEntries = Object.entries(fields).filter(([key]) => key !== 'body');
  $: renderedHtml = renderMarkdown(rendered);
  $: hasSeed = item?.type === 'totp' || fields.seed !== undefined;
  $: linkable = allItems.filter(
    (candidate) =>
      (candidate.type === 'totp' || candidate.type === 'passkey') &&
      !candidate.fields?.login_id &&
      candidate.id !== item?.id
  );

  async function load() {
    error = '';
    try {
      item = await api.show(id, reveal);
      code = '';
      historyPreview = null;
      if (item.type === 'note') {
        rendered = (await api.rendered(id, reveal)).body;
      }
      related = await api.related(id);
      allItems = await api.items();
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
      notice = 'Attachment uploaded';
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

  function removeAttachment() {
    askConfirm('Remove attachment?', 'The encrypted blob is kept until garbage collection.', 'Remove', async () => {
      error = '';
      try {
        await api.edit(id, { delete_fields: ['blob'] });
        notice = 'Attachment removed';
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }

  function restoreHistory(entry) {
    askConfirm(`Restore revision ${entry.rev}?`, 'This creates a new revision; earlier revisions are never rewritten.', 'Restore', async () => {
      error = '';
      try {
        await api.restoreHistory(id, entry.file);
        notice = `Restored revision ${entry.rev}`;
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }

  onMount(async () => {
    try {
      templates = await api.templates();
    } catch (e) {
      error = e.message;
    }
    await load();
  });

  async function toggleFavorite() {
    try {
      await api.edit(id, { favorite: !item.favorite });
      item = { ...item, favorite: !item.favorite };
    } catch (e) {
      error = e.message;
    }
  }

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

  async function linkChild() {
    if (!linkChoice) return;
    error = '';
    try {
      await api.link(id, linkChoice);
      linkChoice = '';
      notice = 'Item linked';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function unlinkChild(childId, parentId = id) {
    error = '';
    try {
      await api.unlink(parentId, childId);
      notice = 'Item unlinked';
      await load();
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

  function renameItem() {
    askPrompt('Rename item', 'Display name', item.name, 'Rename', async (name) => {
      if (!name || name === item.name) return;
      error = '';
      try {
        await api.edit(id, { rename: name });
        await load();
      } catch (e) {
        error = e.message;
      }
    });
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
      notice = 'Changes saved';
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function remove() {
    askConfirm('Delete item?', 'The item is tombstoned for sync safety.', 'Delete', async () => {
      await api.remove(id);
      goto('/items');
    });
  }

  function askConfirm(title, message, label, action) {
    confirmTitle = title;
    confirmMessage = message;
    confirmLabel = label;
    confirmDanger = true;
    confirmAction = action;
    confirmOpen = true;
  }

  function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    action();
  }

  function askPrompt(title, label, value, confirmLabel, action) {
    promptTitle = title;
    promptLabel = label;
    promptValue = value;
    promptConfirmLabel = confirmLabel;
    promptAction = action;
    promptOpen = true;
  }

  function submitPrompt(value) {
    const action = promptAction;
    promptOpen = false;
    action(value);
  }
</script>

{#if item}
  <PageHeader title={item.name} subtitle={`${item.type.replaceAll('_', ' ')} · ${item.id} · rev ${item.rev}`}>
    <svelte:fragment slot="actions">
      <button class:selected={item.favorite} on:click={toggleFavorite}>{item.favorite ? '★ Favorited' : '☆ Favorite'}</button>
      {#if !editing}<button class="primary" on:click={startEdit}>Edit</button>{/if}
      <button on:click={toggle}>{reveal ? 'Mask secrets' : 'Reveal secrets'}</button>
      <button class="danger" on:click={remove}>Delete</button>
    </svelte:fragment>
  </PageHeader>
{:else}
  <PageHeader title="Item" subtitle="Loading..." />
{/if}

{#if error}<p style="color: var(--danger)">{error}</p>{/if}
{#if notice}<p class="dim">{notice}</p>{/if}

{#if item}
  {#if editing}
    <div class="card">
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
    </div>
  {:else}
    <div class="detail-grid">
      <section>
        {#if item.type === 'note'}
          <div class="section-title"><h3>Note</h3><span class="dim">markdown with secret references</span></div>
          <div class="card note">{@html renderedHtml}</div>
        {:else if item.type === 'passkey'}
          <div class="section-title"><h3>Passkey</h3><span class="dim">read-only credential</span></div>
          <div class="card dim">
            Passkey credentials are read-only here. Create and use passkeys from the Chromium
            extension; manage name, folder, tags, and links from the Passkeys page.
          </div>
          <div class="field-table">
            {#each fieldEntries as [key, value]}
              <div class="field-row">
                <span class="field-key">{key}</span>
                <span class="field-value">{value}</span>
                <span class="field-actions"></span>
              </div>
            {/each}
          </div>
          <div class="row" style="margin-top: 10px">
            {#if item.fields.user_name}<button on:click={() => copy('user_name')}>Copy username</button>{/if}
            <button on:click={renameItem}>Rename</button>
          </div>
        {:else}
          <div class="section-title"><h3>Fields</h3><span class="dim">{fieldEntries.length}</span></div>
          {#if fieldEntries.length}
            <div class="field-table">
              {#each fieldEntries as [key, value]}
                <div class="field-row">
                  <span class="field-key">{key}</span>
                  <span class="field-value">{value}</span>
                  <span class="field-actions"><button on:click={() => copy(key)}>Copy</button></span>
                </div>
              {/each}
            </div>
          {:else}
            <div class="empty"><strong>No fields.</strong><span>Edit this item to add data.</span></div>
          {/if}
        {/if}

        {#if item.type !== 'note' && hasSeed}
          <div class="section-title"><h3>TOTP</h3><span class="dim">time-based one-time code</span></div>
          <div class="card">
            <div class="row">
              <button class="primary" on:click={totp}>Generate code</button>
              {#if code}<code style="font-size: 1.15rem; letter-spacing: 0.12em">{code}</code>{/if}
            </div>
          </div>
        {/if}

        {#if item.type === 'login' || related.parent}
          <div class="section-title">
            <h3>Linked items</h3>
            <span class="dim">TOTP and passkeys</span>
          </div>
          <div class="card">
            {#if item.type === 'login'}
              {#if related.children.length}
                {#each related.children as child (child.id)}
                  <div class="row" style="padding: 6px 0; border-bottom: 1px solid var(--line-soft)">
                    <span class={`badge ${child.type}`}>{child.type.replaceAll('_', ' ')}</span>
                    <a class="item-name" href={`/items/${child.id}`}>{child.name}</a>
                    {#if child.fields?.user_name}<span class="dim">{child.fields.user_name}</span>{/if}
                    <span style="flex: 1"></span>
                    <button class="ghost" on:click={() => unlinkChild(child.id)}>Unlink</button>
                  </div>
                {/each}
              {:else}
                <p class="dim">No linked TOTP or passkey items yet.</p>
              {/if}
              <div class="row" style="margin-top: 10px">
                <select bind:value={linkChoice} aria-label="Link item">
                  <option value="">Link a TOTP or passkey...</option>
                  {#each linkable as candidate (candidate.id)}
                    <option value={candidate.id}>{candidate.name} ({candidate.type})</option>
                  {/each}
                </select>
                <button on:click={linkChild} disabled={!linkChoice}>Link</button>
              </div>
            {:else if related.parent}
              <div class="row">
                <span class="dim">Linked to login</span>
                <a class="item-name" href={`/items/${related.parent.id}`}>{related.parent.name}</a>
                <span style="flex: 1"></span>
                <button class="ghost" on:click={() => unlinkChild(item.id, related.parent.id)}>Unlink</button>
              </div>
            {/if}
          </div>
        {/if}
      </section>

      <aside>
        <div class="section-title"><h3>Details</h3></div>
        <div class="card">
          <div class="row" style="justify-content: space-between">
            <span class="dim">Type</span>
            <span class={`badge ${item.type}`}>{item.type.replaceAll('_', ' ')}</span>
          </div>
          <div class="row" style="justify-content: space-between; margin-top: 8px">
            <span class="dim">Folder</span>
            <span>{item.folder || 'root'}</span>
          </div>
          <div class="row" style="justify-content: space-between; margin-top: 8px">
            <span class="dim">Tags</span>
            <span>{item.tags?.length ? item.tags.join(', ') : '—'}</span>
          </div>
          <div class="row" style="justify-content: space-between; margin-top: 8px">
            <span class="dim">Revision</span>
            <span>{item.rev}</span>
          </div>
          {#if related.used_by?.injects?.length}
            <div style="margin-top: 10px">
              <span class="dim">Injected into</span>
              {#each related.used_by.injects as target}
                <div class="item-sub" style="overflow-wrap: anywhere">{target}</div>
              {/each}
            </div>
          {/if}
          {#if related.used_by?.exports?.length}
            <div style="margin-top: 10px">
              <span class="dim">Materialized to</span>
              {#each related.used_by.exports as target}
                <div class="item-sub" style="overflow-wrap: anywhere">{target}</div>
              {/each}
            </div>
          {/if}
          <label style="margin-top: 12px">Clipboard clears after
            <div class="row"><input type="number" min="0" max="600" bind:value={fillTimeout} style="width: 6rem" /> seconds</div>
          </label>
        </div>
      </aside>
    </div>

    <div class="detail-grid" style="margin-top: 18px">
      <section>
        <div class="section-title"><h3>Attachment</h3><span class="dim">encrypted · 25 MiB max</span></div>
        <div class="card">
          {#if item.fields.blob}
            <p class="dim" style="font-family: ui-monospace, monospace; overflow-wrap: anywhere">{item.fields.blob}</p>
            <div class="row">
              <button on:click={downloadAttachment}>Download</button>
              <button class="danger" on:click={removeAttachment}>Remove</button>
            </div>
          {:else}
            <div class="row">
              <input type="file" bind:this={attachInput} />
              <button on:click={uploadAttachment} disabled={uploading}>
                {uploading ? 'Uploading...' : 'Attach file'}
              </button>
            </div>
          {/if}
        </div>
      </section>

      <section>
        <div class="section-title">
          <h3>History</h3><span class="dim">({history.length})</span>
          <span style="flex: 1"></span>
          <button class="ghost" on:click={() => (historyOpen = !historyOpen)}>{historyOpen ? 'Hide' : 'Show'}</button>
        </div>
        <div class="card">
          {#if !historyOpen}
            <p class="dim">Earlier revisions are kept for sync safety. Restoring creates a new revision.</p>
          {:else if !history.length}
            <p class="dim">No earlier revisions.</p>
          {:else}
            {#each history as entry (entry.file)}
              <div class="row" style="border-bottom: 1px solid var(--line-soft); padding: 7px 0">
                <span>rev {entry.rev} · {fmtTime(entry.hlc)}{entry.deleted ? ' [deleted]' : ''}</span>
                <span class="dim">{entry.file}</span>
                <span style="flex: 1"></span>
                <button on:click={() => previewHistory(entry)}>Preview</button>
                <button on:click={() => compareHistory(entry)}>Compare</button>
                <button on:click={() => restoreHistory(entry)}>Restore</button>
              </div>
            {/each}
          {/if}
          {#if historyPreview}
            <div class="card">
              <div class="row">
                <strong>{historyPreview.name}</strong>
                <span class="dim">rev {historyPreview.rev}</span>
                <span style="flex: 1"></span>
                <button on:click={toggleHistoryReveal}>{historyReveal ? 'Mask secrets' : 'Reveal secrets'}</button>
                <button on:click={() => (historyPreview = null)}>Close</button>
              </div>
              {#each Object.entries(historyPreview.fields) as [key, value]}
                <div class="row"><strong>{key}</strong><span>{value}</span></div>
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
        </div>
      </section>
    </div>
  {/if}
{/if}

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmTitle}
  message={confirmMessage}
  confirmLabel={confirmLabel}
  danger={confirmDanger}
  onconfirm={runConfirm}
  onclose={() => (confirmOpen = false)}
/>
<PromptDialog
  bind:open={promptOpen}
  title={promptTitle}
  label={promptLabel}
  value={promptValue}
  confirmLabel={promptConfirmLabel}
  onconfirm={submitPrompt}
  onclose={() => (promptOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
