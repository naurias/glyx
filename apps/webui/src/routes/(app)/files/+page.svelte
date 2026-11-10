<script>
  import { api, pickFile, pickFolder, pickSave } from '$lib/api.js';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import PointerEditor from '$lib/components/PointerEditor.svelte';

  let tab = 'inject';
  let data = { exports: [], injects: [], roots: [] };
  let items = [];
  let tamper = [];
  let error = '';
  let notice = '';

  let managed = {
    kind: 'file',
    itemId: '',
    field: '',
    target: '',
    keep: false,
    perm: '600'
  };
  let track = { target: '', form: 'encrypted-pointer', glob: '*.md' };

  let editor = null;
  let template = '';
  let form = 'encrypted-pointer';
  let materialized = true;
  let preview = null;
  let previewReveal = false;
  let saving = false;
  let refPicker = { line: 1, itemId: '', field: '', form: 'encrypted-pointer', replace: false };

  let createOpen = false;
  let createMode = 'item';
  let createBusy = false;
  let createForm = {
    name: '',
    type: 'generic_key',
    folder: '',
    tags: '',
    fields: [{ key: 'secret', value: '' }]
  };
  let createField = { itemId: '', key: '', value: '' };
  let createPointerFields = {};
  let createPointerEditor = null;

  let merging = null;
  let hunks = [];
  let picks = {};

  const marker = '{{glyx:<item>/<field>}}';

  let confirmOpen = false;
  let confirmTitle = '';
  let confirmMessage = '';
  let confirmAction = () => {};

  $: fileItems = items.filter((item) => item.type === 'file');
  $: selectedItem = items.find((item) => item.id === managed.itemId);
  $: managedFields = selectedItem?.fields ? Object.keys(selectedItem.fields) : [];
  $: refItem = items.find((item) => item.id === refPicker.itemId);
  $: refFields = refItem?.fields ? Object.keys(refItem.fields) : [];
  $: dirty = editor ? template !== editor.template : false;
  $: currentInject = editor ? data.injects.find((inj) => inj.target === editor.target) : null;

  let itemCache = new Map();

  async function fullItem(id) {
    if (!id) return null;
    if (itemCache.has(id)) return itemCache.get(id);
    const item = await api.show(id);
    itemCache.set(id, item);
    return item;
  }

  async function selectManagedItem(id) {
    managed.itemId = id;
    managed.field = '';
    try {
      const item = await fullItem(id);
      if (item) items = items.map((row) => (row.id === id ? { ...row, ...item } : row));
    } catch (e) {
      error = e.message;
    }
  }

  async function selectRefItem(id) {
    refPicker.itemId = id;
    refPicker.field = '';
    try {
      const item = await fullItem(id);
      if (item) items = items.map((row) => (row.id === id ? { ...row, ...item } : row));
    } catch (e) {
      error = e.message;
    }
  }

  async function load() {
    error = '';
    itemCache.clear();
    try {
      const [docs, tamperList, itemList] = await Promise.all([
        api.exports(),
        api.tamper(),
        api.items()
      ]);
      data = docs;
      tamper = tamperList;
      items = itemList;
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  function askConfirm(title, message, action) {
    confirmTitle = title;
    confirmMessage = message;
    confirmAction = action;
    confirmOpen = true;
  }

  function runConfirm() {
    const action = confirmAction;
    confirmOpen = false;
    action();
  }

  async function openEditor(inject) {
    error = '';
    preview = null;
    try {
      const content = await api.injectContent(inject.target);
      editor = content;
      template = content.template;
      form = content.form;
      materialized = content.status !== 'locked';
      refPicker.line = Math.max(1, content.template.split('\n').length);
      tab = 'inject';
    } catch (e) {
      error = e.message;
    }
  }

  async function loadPreview() {
    if (!editor) return;
    error = '';
    try {
      preview = await api.injectPreview(editor.target, previewReveal);
    } catch (e) {
      error = e.message;
    }
  }

  function refFormMap() {
    const map = {};
    for (const ref of editor?.refs || []) map[`${ref.item_id}/${ref.field}`] = ref.form;
    return map;
  }

  async function saveEditor(forced = {}) {
    if (!editor) return;
    error = '';
    saving = true;
    const refMap = { ...refFormMap(), ...(forced.ref_forms || {}) };
    try {
      const saved = await api.saveInject({
        target: editor.target,
        template,
        form,
        expected_hash: editor.hash,
        materialized,
        ref_forms: refMap
      });
      editor = saved;
      template = saved.template;
      preview = null;
      notice = `Saved ${saved.target} (${saved.status})`;
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      saving = false;
    }
  }

  async function changeRefForm(ref, next) {
    error = '';
    saving = true;
    try {
      const refMap = refFormMap();
      refMap[`${ref.item_id}/${ref.field}`] = next;
      const saved = await api.saveInject({
        target: editor.target,
        template,
        form,
        expected_hash: editor.hash,
        materialized,
        ref_forms: refMap
      });
      editor = saved;
      template = saved.template;
      notice = `${ref.item_name}:${ref.field} now uses ${next}`;
      await load();
    } catch (e) {
      error = e.message;
    } finally {
      saving = false;
    }
  }

  function parseRefValue(value) {
    const match = String(value || '')
      .trim()
      .match(/^\{\{glyx:([0-9a-fA-F-]{36})\/([a-z0-9_]+)\}\}$/);
    return match ? { itemId: match[1], field: match[2] } : null;
  }

  async function expandRef(itemId, field, depth = 0) {
    const item = await fullItem(itemId);
    if (!item) throw new Error('source item not found');
    if (item.type !== 'pointer') return { itemId, field, item };
    if (depth > 5) throw new Error('pointer chain is too deep');
    const value = item.fields?.[field];
    const parsed = parseRefValue(value);
    if (!parsed) throw new Error(`pointer alias ${item.name}:${field} has no valid target`);
    return expandRef(parsed.itemId, parsed.field, depth + 1);
  }

  async function insertRef(itemId, field, form) {
    const expanded = await expandRef(itemId, field);
    const placeholder = `{{glyx:${expanded.itemId}/${expanded.field}}}`;
    const lines = template.split('\n');
    if (refPicker.line < 1 || refPicker.line > lines.length) {
      throw new Error(`Line ${refPicker.line} is out of range (${lines.length} lines).`);
    }
    if (refPicker.replace) lines[refPicker.line - 1] = placeholder;
    else lines[refPicker.line - 1] += placeholder;
    template = lines.join('\n');
    await saveEditor({
      ref_forms: { [`${expanded.itemId}/${expanded.field}`]: form }
    });
    if (expanded.itemId !== itemId || expanded.field !== field) {
      notice = `Inserted ${expanded.item.name}:${expanded.field} from a pointer alias`;
    }
  }

  async function addRef() {
    if (!refPicker.itemId || !refPicker.field) {
      error = 'Choose a source item and field first.';
      return;
    }
    error = '';
    try {
      await insertRef(refPicker.itemId, refPicker.field, refPicker.form);
    } catch (e) {
      error = e.message;
    }
  }

  function removeRef(ref) {
    const placeholder = `{{glyx:${ref.item_id}/${ref.field}}}`;
    template = template.split(placeholder).join('');
    saveEditor();
  }

  function openCreate(mode) {
    createMode = mode;
    createBusy = false;
    createForm = {
      name: '',
      type: 'generic_key',
      folder: '',
      tags: '',
      fields: [{ key: 'secret', value: '' }]
    };
    createField = { itemId: refPicker.itemId, key: '', value: '' };
    createPointerFields = {};
    createOpen = true;
  }

  function splitTags(text) {
    return text
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean);
  }

  function normalizeFieldKey(key) {
    return key
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/^_+/, '');
  }

  function createFieldRows() {
    const out = {};
    for (const row of createForm.fields) {
      const key = normalizeFieldKey(row.key || '');
      if (key && row.value !== '') out[key] = row.value;
    }
    return out;
  }

  async function createItemForPointer() {
    error = '';
    const fields = createFieldRows();
    if (!createForm.name.trim()) {
      error = 'Name is required.';
      return;
    }
    if (!Object.keys(fields).length) {
      error = 'Add at least one field with content.';
      return;
    }
    createBusy = true;
    try {
      const res = await api.create({
        type: createForm.type,
        name: createForm.name,
        folder: createForm.folder,
        tags: splitTags(createForm.tags),
        fields
      });
      const first = Object.keys(fields)[0];
      createOpen = false;
      await load();
      refPicker.itemId = res.id;
      refPicker.field = first;
      await insertRef(res.id, first, refPicker.form);
      notice = `Created ${createForm.name} and inserted ${first}`;
    } catch (e) {
      error = e.message;
    } finally {
      createBusy = false;
    }
  }

  async function createFieldForPointer() {
    error = '';
    const key = normalizeFieldKey(createField.key || '');
    if (!createField.itemId || !key || createField.value === '') {
      error = 'Choose an item and fill the field key and content.';
      return;
    }
    createBusy = true;
    try {
      await api.edit(createField.itemId, { fields: { [key]: createField.value } });
      createOpen = false;
      await load();
      refPicker.itemId = createField.itemId;
      refPicker.field = key;
      await insertRef(createField.itemId, key, refPicker.form);
      notice = `Added ${key} and inserted the reference`;
    } catch (e) {
      error = e.message;
    } finally {
      createBusy = false;
    }
  }

  async function createPointerItem() {
    error = '';
    const fields = createPointerEditor?.fields() || {};
    if (!createForm.name.trim()) {
      error = 'Name is required.';
      return;
    }
    if (!Object.keys(fields).length) {
      error = 'Add at least one alias with a target item and field.';
      return;
    }
    createBusy = true;
    try {
      const res = await api.create({
        type: 'pointer',
        name: createForm.name,
        folder: createForm.folder,
        tags: splitTags(createForm.tags),
        fields
      });
      const first = Object.keys(fields)[0];
      createOpen = false;
      await load();
      refPicker.itemId = res.id;
      refPicker.field = first;
      await insertRef(res.id, first, refPicker.form);
      notice = `Created pointer ${createForm.name} and inserted ${first}`;
    } catch (e) {
      error = e.message;
    } finally {
      createBusy = false;
    }
  }

  function addCreateFieldRow() {
    createForm.fields = [...createForm.fields, { key: '', value: '' }];
  }

  function removeCreateFieldRow(index) {
    createForm.fields = createForm.fields.filter((_, i) => i !== index);
  }

  async function addManaged() {
    error = '';
    if (!managed.target) {
      error = 'Choose a target path.';
      return;
    }
    if (!managed.itemId) {
      error = managed.kind === 'file' ? 'Choose a file item.' : 'Choose a source item.';
      return;
    }
    try {
      const body = {
        target: managed.target,
        kind: managed.kind,
        item: managed.itemId,
        keep: managed.keep,
        perm: parseInt(managed.perm || '600', 8)
      };
      if (managed.kind === 'field') body.field = managed.field;
      await api.addExport(body);
      await api.targetUnlock(managed.target);
      notice = `${managed.target} materialized from the vault`;
      managed.target = '';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function pickManagedTarget() {
    const path = await pickSave('Choose where to write the file');
    if (path) managed.target = path;
  }

  async function pickTrackTarget() {
    const path = await pickFile('Choose a file to track');
    if (path) track.target = path;
  }

  async function pickTrackFolder() {
    const path = await pickFolder('Choose a folder to track');
    if (path) track.target = path;
  }

  async function trackInject() {
    error = '';
    try {
      await api.trackInject(track.target, track.form, track.glob);
      notice = `Tracking ${track.target}`;
      track.target = '';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function scan() {
    error = '';
    try {
      await api.scanInjects();
      notice = 'Tracked folders scanned';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function tUnlock(target) {
    error = '';
    try {
      await api.targetUnlock(target);
      notice = `Unlocked ${target}`;
      await load();
      if (editor?.target === target) await openEditor(editor);
    } catch (e) {
      error = e.message;
    }
  }

  async function tLock(target) {
    error = '';
    try {
      await api.targetLock(target);
      notice = `Locked ${target}`;
      await load();
      if (editor?.target === target) await openEditor(editor);
    } catch (e) {
      error = e.message;
    }
  }

  async function tMove(target) {
    const next = await pickFile('Choose the new location');
    if (!next || next === target) return;
    error = '';
    try {
      await api.targetMove(target, next);
      notice = `Moved ${target}`;
      if (editor?.target === target) editor = null;
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function forget(target) {
    askConfirm('Stop tracking?', `${target} will be released from glyx.`, async () => {
      error = '';
      try {
        await api.recall(target);
        if (editor?.target === target) editor = null;
        notice = `${target} is no longer tracked`;
        await load();
      } catch (e) {
        error = e.message;
      }
    });
  }

  async function toggleKeep(exp) {
    error = '';
    try {
      await api.updateExport(exp.target, { keep: !exp.keep });
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function setInjectPolicy(inj, value) {
    error = '';
    const lockOnExit = value === 'always' ? true : value === 'never' ? false : null;
    try {
      await api.updateInject(inj.target, lockOnExit);
      await load();
      if (editor?.target === inj.target) await openEditor(editor);
    } catch (e) {
      error = e.message;
    }
  }

  function policyValue(inj) {
    return inj.lock_on_exit === true ? 'always' : inj.lock_on_exit === false ? 'never' : 'inherit';
  }

  async function resolveTamper(target, action) {
    try {
      await api.resolveTamper(target, action);
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  async function openMerge(target) {
    try {
      const res = await api.mergePreview(target);
      merging = target;
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

  function statusBadge(status) {
    return status || 'unknown';
  }
</script>

<PageHeader
  title="Files & Injection"
  subtitle="Managed files are whole secrets written from the vault. In-place injection keeps your own file and only swaps marked values."
>
  <svelte:fragment slot="actions">
    <button class={tab === 'inject' ? 'active' : ''} on:click={() => (tab = 'inject')}>In-place injection</button>
    <button class={tab === 'managed' ? 'active' : ''} on:click={() => (tab = 'managed')}>Managed files</button>
    <button class={tab === 'folders' ? 'active' : ''} on:click={() => (tab = 'folders')}>Folders</button>
  </svelte:fragment>
</PageHeader>

{#if error}<p style="color: var(--danger)">{error}</p>{/if}
{#if notice}<p class="dim">{notice}</p>{/if}

{#if tamper.length}
  <div class="card">
    <strong>Tamper detected</strong>
    <p class="dim">These targets changed outside glyx. Re-materialize from the vault or stop tracking.</p>
    {#each tamper as t}
      {@const tgt = typeof t === 'string' ? t : t.target || ''}
      <div class="row">
        <span>{typeof t === 'string' ? t : `${t.target} (${t.kind})`}</span>
        <span style="flex: 1"></span>
        {#if tgt}
          <button on:click={() => resolveTamper(tgt, 'keep')}>Keep file</button>
          <button class="danger" on:click={() => resolveTamper(tgt, 'restore')}>Restore vault copy</button>
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
          <div class="dim">hunk {i}{h.secret ? ' · secret' : ''}</div>
          <div><strong>File</strong><pre>{h.theirs.join('\n')}</pre></div>
          <div><strong>glyx</strong><pre>{h.ours.join('\n')}</pre></div>
          <div class="row">
            <button class:active={picks[i] === 'theirs'} on:click={() => (picks[i] = 'theirs')}>Keep file</button>
            <button class:active={picks[i] === 'ours'} on:click={() => (picks[i] = 'ours')}>Keep glyx</button>
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

{#if tab === 'managed'}
  <div class="card">
    <h3>What is a managed file?</h3>
    <p class="dim">
      The whole file is stored encrypted in the vault. glyx writes a plaintext copy while the vault
      is unlocked and removes it on lock unless you choose to keep it.
    </p>
  </div>

  <div class="section-title"><h3>Materialize a file</h3></div>
  <div class="card">
    <div class="row">
      <label>Source
        <select bind:value={managed.kind}>
          <option value="file">File item</option>
          <option value="field">Item field</option>
        </select>
      </label>
      <label>Item
        <select value={managed.itemId} on:change={(e) => selectManagedItem(e.currentTarget.value)}>
          <option value="">Choose item...</option>
          {#each managed.kind === 'file' ? fileItems : items as item (item.id)}
            <option value={item.id}>{item.name}</option>
          {/each}
        </select>
      </label>
      {#if managed.kind === 'field'}
        <label>Field
          <select bind:value={managed.field}>
            <option value="">Choose field...</option>
            {#each managedFields as field}
              <option value={field}>{field}</option>
            {/each}
          </select>
        </label>
      {/if}
      <label>Target path
        <div class="row tight">
          <input bind:value={managed.target} placeholder="/path/to/destination" style="min-width: 260px" />
          <button on:click={pickManagedTarget}>Browse</button>
        </div>
      </label>
      <label>Permissions
        <input bind:value={managed.perm} style="width: 5rem" />
      </label>
      <label class="row"><input type="checkbox" bind:checked={managed.keep} /> keep on lock</label>
      <button class="primary" on:click={addManaged}>Materialize</button>
    </div>
    {#if managed.kind === 'file' && !fileItems.length}
      <p class="dim">No file items yet. Add one from Items → Add item → File.</p>
    {/if}
  </div>

  <div class="section-title"><h3>Managed files</h3><span class="dim">{data.exports.length}</span></div>
  {#if data.exports.length}
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr><th>Target</th><th>Source</th><th>Lock behavior</th><th>Mode</th><th></th></tr>
        </thead>
        <tbody>
          {#each data.exports as exp (exp.target)}
            <tr>
              <td class="item-name">{exp.target}</td>
              <td class="dim">{exp.kind}{exp.field ? ` · ${exp.field}` : ''}</td>
              <td>{exp.keep ? 'keep' : 'remove on lock'}</td>
              <td><span class="chip">{(exp.perm ?? 0o600).toString(8)}</span></td>
              <td class="cell-actions">
                <button on:click={() => tUnlock(exp.target)}>Materialize</button>
                <button on:click={() => tLock(exp.target)}>Lock</button>
                <button on:click={() => toggleKeep(exp)}>{exp.keep ? 'Remove on lock' : 'Keep on lock'}</button>
                <button on:click={() => tMove(exp.target)}>Move</button>
                <button class="danger" on:click={() => forget(exp.target)}>Forget</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="empty"><strong>No managed files.</strong><span>Materialize a file item or a single field.</span></div>
  {/if}
{/if}

{#if tab === 'inject'}
  <div class="card">
    <h3>What is in-place injection?</h3>
    <p class="dim">
      The file stays where it is. You mark values with <code>{marker}</code>.
      While unlocked glyx writes plaintext in place; on lock it swaps each value for the selected
      locked form. Your text and formatting are preserved.
    </p>
  </div>

  <div class="detail-grid">
    <section>
      <div class="section-title">
        <h3>Tracked files</h3><span class="dim">{data.injects.length}</span>
      </div>
      {#if data.injects.length}
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Target</th><th>Status</th><th>Form</th><th>Lock on exit</th><th></th></tr></thead>
            <tbody>
              {#each data.injects as inj (inj.target)}
                <tr class:selected-row={editor?.target === inj.target}>
                  <td class="item-name">{inj.target}</td>
                  <td><span class="chip {statusBadge(inj.status)}">{inj.status}</span></td>
                  <td class="dim">{inj.form}</td>
                  <td>
                    <select value={policyValue(inj)} on:change={(e) => setInjectPolicy(inj, e.currentTarget.value)} aria-label="Lock on exit">
                      <option value="inherit">inherit</option>
                      <option value="always">always</option>
                      <option value="never">never</option>
                    </select>
                  </td>
                  <td class="cell-actions">
                    <button on:click={() => openEditor(inj)}>Edit</button>
                    <button on:click={() => tUnlock(inj.target)}>Unlock</button>
                    <button on:click={() => tLock(inj.target)}>Lock</button>
                    <button on:click={() => openMerge(inj.target)}>Merge</button>
                    <button class="danger" on:click={() => forget(inj.target)}>Forget</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="empty"><strong>No in-place files.</strong><span>Track a file below, then edit its template.</span></div>
      {/if}

      <div class="section-title"><h3>Track a file</h3></div>
      <div class="card">
        <div class="row">
          <input bind:value={track.target} placeholder="/path/to/file" style="flex: 1" />
          <button on:click={pickTrackTarget}>Browse</button>
          <select bind:value={track.form} aria-label="Locked form">
            <option value="encrypted-pointer">encrypted-pointer</option>
            <option value="masked">masked</option>
            <option value="ref">ref</option>
          </select>
          <button class="primary" on:click={trackInject} disabled={!track.target}>Track</button>
        </div>
        <p class="dim">encrypted-pointer is recommended: path-bound and does not depend on the ledger.</p>
      </div>
    </section>

    <aside>
      <div class="section-title"><h3>Source items</h3><span class="dim">{items.length}</span></div>
      <div class="card">
        <p class="dim">Insert a reference at a line of the open template.</p>
        {#if editor}
          <label>Line
            <input type="number" min="1" bind:value={refPicker.line} />
          </label>
          <label>Item
            <select value={refPicker.itemId} on:change={(e) => selectRefItem(e.currentTarget.value)}>
              <option value="">Choose item...</option>
              {#each items as item (item.id)}
                <option value={item.id}>{item.name} ({item.type.replaceAll('_', ' ')})</option>
              {/each}
            </select>
          </label>
          <label>Field
            <select bind:value={refPicker.field}>
              <option value="">Choose field...</option>
              {#each refFields as field}
                <option value={field}>{field}</option>
              {/each}
            </select>
          </label>
          <p class="dim">Pointer items expand to their target field when inserted.</p>
          <div class="row">
            <button on:click={() => openCreate('item')}>New item</button>
            <button on:click={() => openCreate('field')}>New field</button>
            <button on:click={() => openCreate('pointer')}>New pointer</button>
          </div>
          <label>Locked form
            <select bind:value={refPicker.form}>
              <option value="encrypted-pointer">encrypted-pointer</option>
              <option value="masked">masked</option>
              <option value="ref">ref</option>
            </select>
          </label>
          <label class="row"><input type="checkbox" bind:checked={refPicker.replace} /> replace the whole line</label>
          <button class="primary" on:click={addRef}>Insert reference</button>
        {:else}
          <p class="dim">Open a tracked file to insert references.</p>
        {/if}
      </div>
    </aside>
  </div>

  {#if editor}
    <div class="section-title">
      <h3>Editing {editor.target}</h3>
      <span class="chip {editor.status}">{editor.status}</span>
      {#if dirty}<span class="chip active">unsaved</span>{/if}
    </div>
    <div class="detail-grid">
      <section>
        <div class="card">
          <div class="row" style="justify-content: space-between">
            <label class="row">Default locked form
              <select bind:value={form} on:change={() => saveEditor()}>
                <option value="encrypted-pointer">encrypted-pointer</option>
                <option value="masked">masked</option>
                <option value="ref">ref</option>
              </select>
            </label>
            <label class="row"><input type="checkbox" bind:checked={materialized} /> write unlocked values</label>
          </div>
          <textarea
            bind:value={template}
            spellcheck="false"
            class="template-editor"
            aria-label="Injection template"
          ></textarea>
          <div class="row" style="justify-content: flex-end">
            <button on:click={() => (template = editor.template)} disabled={!dirty}>Revert</button>
            <button class="primary" on:click={() => saveEditor()} disabled={saving}>
              {saving ? 'Saving...' : 'Save template'}
            </button>
          </div>
        </div>

        <div class="section-title"><h3>Preview</h3></div>
        <div class="card">
          <div class="row">
            <button on:click={loadPreview}>Render preview</button>
            <label class="row"><input type="checkbox" bind:checked={previewReveal} on:change={loadPreview} /> reveal secrets</label>
          </div>
          {#if preview}
            <div class="preview-grid">
              <div>
                <div class="filter-title">Unlocked</div>
                <pre>{preview.unlocked}</pre>
              </div>
              <div>
                <div class="filter-title">Locked</div>
                <pre>{preview.locked}</pre>
              </div>
            </div>
          {:else}
            <p class="dim">Render to see exactly what is written in each state.</p>
          {/if}
        </div>
      </section>

      <aside>
        <div class="section-title"><h3>References</h3><span class="dim">{editor.refs.length}</span></div>
        <div class="card">
          {#if editor.refs.length}
            {#each editor.refs as ref (ref.item_id + '/' + ref.field)}
              <div class="ref-card">
                <div class="row">
                  <strong>{ref.item_name}</strong>
                  <span class="dim">{ref.field}</span>
                  {#if ref.secret}<span class="badge">secret</span>{/if}
                </div>
                <div class="field-value">{ref.value}</div>
                <div class="row">
                  <select value={ref.form} on:change={(e) => changeRefForm(ref, e.currentTarget.value)}>
                    <option value="encrypted-pointer">encrypted-pointer</option>
                    <option value="masked">masked</option>
                    <option value="ref">ref</option>
                  </select>
                  <button class="danger" on:click={() => removeRef(ref)}>Remove</button>
                </div>
              </div>
            {/each}
          {:else}
            <p class="dim">No references in this template yet.</p>
          {/if}
        </div>
        <div class="section-title"><h3>Actions</h3></div>
        <div class="card">
          {#if currentInject}
            <label>Lock on exit
              <select
                value={policyValue(currentInject)}
                on:change={(e) => setInjectPolicy(currentInject, e.currentTarget.value)}
              >
                <option value="inherit">inherit global setting</option>
                <option value="always">always lock</option>
                <option value="never">never lock</option>
              </select>
            </label>
          {/if}
          <div class="row">
            <button on:click={() => tUnlock(editor.target)}>Unlock file</button>
            <button on:click={() => tLock(editor.target)}>Lock file</button>
          </div>
          <div class="row" style="margin-top: 8px">
            <button class="danger" on:click={() => forget(editor.target)}>Forget tracking</button>
          </div>
        </div>
      </aside>
    </div>
  {/if}
{/if}

{#if tab === 'folders'}
  <div class="card">
    <h3>Tracked folders</h3>
    <p class="dim">
      New files matching the glob are registered for injection automatically when the folders are
      scanned. Each file keeps its own template and references.
    </p>
    <div class="row">
      <input bind:value={track.target} placeholder="/path/to/folder" style="flex: 1" />
      <button on:click={pickTrackFolder}>Browse</button>
      <input bind:value={track.glob} placeholder="*.md" />
      <select bind:value={track.form}>
        <option value="encrypted-pointer">encrypted-pointer</option>
        <option value="masked">masked</option>
        <option value="ref">ref</option>
      </select>
      <button class="primary" on:click={trackInject} disabled={!track.target}>Track folder</button>
      <button on:click={scan}>Scan now</button>
    </div>
  </div>

  {#if data.roots.length}
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Folder</th><th>Glob</th><th>Form</th><th></th></tr></thead>
        <tbody>
          {#each data.roots as root (root.root)}
            <tr>
              <td class="item-name">{root.root}</td>
              <td class="dim">{root.glob}</td>
              <td class="dim">{root.form}</td>
              <td class="cell-actions">
                <button on:click={() => tUnlock(root.root)}>Unlock</button>
                <button on:click={() => tLock(root.root)}>Lock</button>
                <button class="danger" on:click={() => forget(root.root)}>Forget</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="empty"><strong>No tracked folders.</strong><span>Add a folder above to manage many files at once.</span></div>
  {/if}
{/if}

<Modal bind:open={createOpen} title="Create a source for the pointer" onclose={() => (createOpen = false)}>
  <div class="row">
    <button class:active={createMode === 'item'} on:click={() => (createMode = 'item')}>New item</button>
    <button class:active={createMode === 'field'} on:click={() => (createMode = 'field')}>New field</button>
    <button class:active={createMode === 'pointer'} on:click={() => (createMode = 'pointer')}>New pointer item</button>
  </div>

  {#if createMode !== 'field'}
    <label>Name<input bind:value={createForm.name} placeholder="source name" /></label>
    <label>Folder<input bind:value={createForm.folder} placeholder="optional" /></label>
    <label>Tags<input bind:value={createForm.tags} placeholder="comma, separated" /></label>
  {/if}

  {#if createMode === 'item'}
    <label>Type
      <select bind:value={createForm.type}>
        <option value="generic_key">Generic key</option>
        <option value="login">Login</option>
        <option value="note">Note</option>
        <option value="identity">Identity</option>
        <option value="card">Card</option>
        <option value="totp">TOTP</option>
        <option value="file">File</option>
        <option value="ssh_key">SSH key</option>
      </select>
    </label>
    <p class="dim">Add the fields you want to reference. Custom fields are stored as plain content; use a type template for secret masking.</p>
    {#each createForm.fields as row, index}
      <div class="row">
        <input bind:value={row.key} placeholder="field_key" />
        <input bind:value={row.value} placeholder="content" style="flex: 1" />
        <button on:click={() => removeCreateFieldRow(index)}>Remove</button>
      </div>
    {/each}
    <button on:click={addCreateFieldRow}>Add field</button>
  {:else if createMode === 'field'}
    <label>Item
      <select value={createField.itemId} on:change={(e) => (createField.itemId = e.currentTarget.value)}>
        <option value="">Choose item...</option>
        {#each items.filter((item) => item.type !== 'pointer') as item (item.id)}
          <option value={item.id}>{item.name}</option>
        {/each}
      </select>
    </label>
    <label>Field key<input bind:value={createField.key} placeholder="field_key" /></label>
    <label>Content<input bind:value={createField.value} placeholder="value" /></label>
  {:else}
    <PointerEditor
      items={items}
      bind:this={createPointerEditor}
      onchange={(fields) => (createPointerFields = fields)}
      disabled={createBusy}
    />
  {/if}

  <svelte:fragment slot="actions">
    <button on:click={() => (createOpen = false)} disabled={createBusy}>Cancel</button>
    {#if createMode === 'item'}
      <button class="primary" on:click={createItemForPointer} disabled={createBusy}>
        {createBusy ? 'Creating...' : 'Create and insert'}
      </button>
    {:else if createMode === 'field'}
      <button class="primary" on:click={createFieldForPointer} disabled={createBusy}>
        {createBusy ? 'Adding...' : 'Add field and insert'}
      </button>
    {:else}
      <button class="primary" on:click={createPointerItem} disabled={createBusy}>
        {createBusy ? 'Creating...' : 'Create pointer and insert'}
      </button>
    {/if}
  </svelte:fragment>
</Modal>

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmTitle}
  message={confirmMessage}
  confirmLabel="Confirm"
  danger
  onconfirm={runConfirm}
  onclose={() => (confirmOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
