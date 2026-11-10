<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';

  export let items = [];
  export let initialFields = {};
  export let disabled = false;
  export let onchange = () => {};

  let rows = [];
  let fieldCache = new Map();

  $: sourceItems = items.filter((item) => item.type !== 'pointer');

  onMount(() => {
    hydrate();
  });

  function parseRef(value) {
    const match = String(value || '')
      .trim()
      .match(/^\{\{glyx:([0-9a-fA-F-]{36})\/([a-z0-9_]+)\}\}$/);
    return match ? { itemId: match[1], field: match[2] } : null;
  }

  function hydrate() {
    rows = Object.entries(initialFields || {}).map(([key, value]) => {
      const parsed = parseRef(value);
      return {
        key,
        itemId: parsed?.itemId || '',
        field: parsed?.field || '',
        fields: [],
        invalid: !parsed
      };
    });
    for (const row of rows) {
      if (row.itemId) loadFields(row);
    }
    emit();
  }

  async function fieldsFor(itemId) {
    if (!itemId) return [];
    if (fieldCache.has(itemId)) return fieldCache.get(itemId);
    const item = await api.show(itemId);
    const fields = Object.keys(item.fields || {});
    fieldCache.set(itemId, fields);
    return fields;
  }

  async function loadFields(row) {
    try {
      row.fields = await fieldsFor(row.itemId);
      rows = rows;
    } catch {
      row.fields = [];
    }
  }

  async function selectItem(row, itemId) {
    row.itemId = itemId;
    row.field = '';
    row.invalid = false;
    await loadFields(row);
    emit();
  }

  function selectField(row, field) {
    row.field = field;
    row.invalid = false;
    emit();
  }

  function updateKey(row, value) {
    row.key = value
      .toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/^_+/, '');
    emit();
  }

  function addRow() {
    rows = [...rows, { key: `alias_${rows.length + 1}`, itemId: '', field: '', fields: [], invalid: false }];
    emit();
  }

  function removeRow(index) {
    rows = rows.filter((_, i) => i !== index);
    emit();
  }

  function getFields() {
    const out = {};
    for (const row of rows) {
      if (row.key && row.itemId && row.field) {
        out[row.key] = `{{glyx:${row.itemId}/${row.field}}}`;
      }
    }
    return out;
  }

  function emit() {
    onchange(getFields());
  }

  export function fields() {
    return getFields();
  }
</script>

<div class="card">
  <p class="dim">
    Each alias points at a field on another item. The injection editor expands the alias to that
    real reference when you insert it.
  </p>
  {#if rows.length}
    {#each rows as row, index}
      <div class="row" style="align-items: flex-end; border-bottom: 1px solid var(--line-soft); padding: 8px 0">
        <label>Alias
          <input
            value={row.key}
            on:input={(e) => updateKey(row, e.currentTarget.value)}
            placeholder="prod_password"
            {disabled}
          />
        </label>
        <label>Target item
          <select
            value={row.itemId}
            on:change={(e) => selectItem(row, e.currentTarget.value)}
            {disabled}
          >
            <option value="">Choose item...</option>
            {#each sourceItems as source (source.id)}
              <option value={source.id}>{source.name} ({source.type.replaceAll('_', ' ')})</option>
            {/each}
          </select>
        </label>
        <label>Target field
          <select
            value={row.field}
            on:change={(e) => selectField(row, e.currentTarget.value)}
            disabled={disabled || !row.itemId}
          >
            <option value="">Choose field...</option>
            {#each row.fields || [] as field}
              <option value={field}>{field}</option>
            {/each}
          </select>
        </label>
        <button type="button" class="danger" on:click={() => removeRow(index)} disabled={disabled}>Remove</button>
      </div>
      {#if row.invalid}
        <p class="dim">This alias does not contain a valid reference.</p>
      {/if}
    {/each}
  {:else}
    <p class="dim">No aliases yet.</p>
  {/if}
  <button type="button" on:click={addRow} disabled={disabled}>Add alias</button>
</div>
