<script>
  import { renderMarkdown } from './markdown.js';
  import { generatePassword } from './pass.js';
  import { api } from './api.js';
  import { parseOtpauth } from './totp.js';
  import { canScanQr, pasteTotp, scanTotp } from './totp-capture.js';

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
  let captureError = '';
  let scanning = false;

  $: fieldSpecs = (templates.find((t) => t.type === item_type)?.fields ?? []).filter(
    (f) => f.name !== 'login_id'
  );
  $: preview = renderMarkdown(form.body ?? '');
  $: scanner = canScanQr();

  function generate(field) {
    form[field] = generatePassword(field === 'password' ? 24 : 32);
    form = { ...form };
  }

  async function applyTotp(raw) {
    captureError = '';
    const text = String(raw || '').trim();
    if (!text) return;
    form.seed = text;
    let parsed = parseOtpauth(text);
    if (text.toLowerCase().startsWith('otpauth://')) {
      try {
        const info = await api.parseTotp({ uri: text });
        if (info?.ok) {
          parsed = {
            issuer: info.issuer || '',
            account: info.account || '',
            digits: info.digits,
            period: info.period
          };
        }
      } catch {
        // Keep the local parse when the daemon is unavailable.
      }
    }
    if (parsed) {
      if (parsed.digits) form.digits = String(parsed.digits);
      if (parsed.period) form.period = String(parsed.period);
      if (!name.trim()) {
        name = parsed.issuer
          ? parsed.account
            ? `${parsed.issuer} (${parsed.account})`
            : parsed.issuer
          : parsed.account || '';
      }
    }
    form = { ...form };
  }

  async function scan() {
    captureError = '';
    scanning = true;
    try {
      applyTotp(await scanTotp());
    } catch (e) {
      captureError = e.message || String(e);
    } finally {
      scanning = false;
    }
  }

  async function paste() {
    captureError = '';
    try {
      applyTotp(await pasteTotp());
    } catch (e) {
      captureError = e.message || String(e);
    }
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
          placeholder={f.name === 'seed' ? 'base32 secret or otpauth:// URI' : ''}
          style="flex: 1"
        />
        {#if f.secret}
          <button type="button" on:click={() => generate(f.name)}>Generate</button>
        {/if}
        {#if f.name === 'seed' && item_type === 'totp'}
          {#if scanner}
            <button type="button" on:click={scan} disabled={scanning}>
              {scanning ? 'Scanning…' : 'Scan QR'}
            </button>
          {/if}
          <button type="button" on:click={paste}>Paste</button>
        {/if}
      </div>
    </label>
    {#if f.name === 'seed' && item_type === 'totp' && captureError}
      <p class="dim" style="color: var(--danger); margin: 0 0 8px">{captureError}</p>
    {/if}
  {/each}
{/if}
<div class="row" style="margin-top: 8px">
  <button class="primary" on:click={submit} disabled={busy}>{submitLabel}</button>
  {#if oncancel}<button on:click={oncancel}>Cancel</button>{/if}
</div>
