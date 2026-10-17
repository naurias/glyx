<script>
  import { renderMarkdown } from './markdown.js';
  import { generatePassword } from './pass.js';

  export let templates = [];
  export let item_type = 'login';
  export let name = '';
  export let folder = '';
  export let values = {};
  export let tags = [];
  export let lockType = false;
  export let submitLabel = 'Save';
  export let busy = false;
  export let onsubmit = () => {};
  export let oncancel = null;

  let form = { ...values };
  let tagText = (tags || []).join(', ');

  $: fieldSpecs = templates.find((t) => t.type === item_type)?.fields ?? [];
  $: preview = renderMarkdown(form.body ?? '');

  function generate(field) {
    form[field] = generatePassword(field === 'password' ? 24 : 32);
    form = { ...form };
  }

  function submit() {
    const clean = {};
    for (const [k, v] of Object.entries(form)) {
      if (k && v !== '' && v !== null && v !== undefined) clean[k] = v;
    }
    onsubmit({
      type: item_type,
      name,
      folder,
      tags: tagText
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      fields: clean
    });
  }
</script>

<label>Type
  <select bind:value={item_type} disabled={lockType}>
    {#each templates as t}
      <option value={t.type}>{t.type}</option>
    {/each}
  </select>
</label>
<label>Name<input bind:value={name} /></label>
<label>Folder<input bind:value={folder} /></label>
<label>Tags<input bind:value={tagText} placeholder="comma, separated" /></label>
{#if item_type === 'note'}
  <label>Note (markdown)
    <textarea bind:value={form.body} rows="10"></textarea>
  </label>
  <div class="card note">{@html preview}</div>
{:else}
  {#each fieldSpecs as f}
    <label>{f.name}{f.required ? ' *' : ''}
      <div class="row">
        <input
          type={f.secret ? 'password' : 'text'}
          bind:value={form[f.name]}
          style="flex: 1"
        />
        {#if f.secret}
          <button type="button" on:click={() => generate(f.name)}>Generate</button>
        {/if}
      </div>
    </label>
  {/each}
{/if}
<div class="row" style="margin-top: 8px">
  <button class="primary" on:click={submit} disabled={busy}>{submitLabel}</button>
  {#if oncancel}<button on:click={oncancel}>Cancel</button>{/if}
</div>
