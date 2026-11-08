<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import PromptDialog from '$lib/components/PromptDialog.svelte';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';

  let data = {
    agent: { running: false, socket: '', identities: 0 },
    keys: []
  };
  let error = '';
  let notice = '';
  let busy = false;

  let generateOpen = false;
  let importOpen = false;
  let gen = {
    name: '',
    kind: 'ed25519',
    comment: '',
    folder: '',
    tags: '',
    add_to_agent: false
  };
  let imp = {
    private_key: '',
    passphrase: '',
    name: '',
    comment: '',
    folder: '',
    tags: '',
    add_to_agent: false
  };

  let exportKey = null;
  let exportTarget = '';
  let exportOpen = false;
  let deleteKey = null;
  let confirmOpen = false;
  let fileInput;

  $: supported = data.keys.filter((key) => key.agent_supported);
  $: missing = supported.filter((key) => !key.agent_enabled);
  $: unsupported = data.keys.filter((key) => !key.agent_supported);

  async function load() {
    error = '';
    try {
      data = await api.ssh();
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  async function copy(text, label = 'Copied') {
    try {
      await navigator.clipboard.writeText(text);
      notice = label;
    } catch (e) {
      error = e.message;
    }
  }

  async function toggle(key) {
    error = '';
    busy = true;
    try {
      const res = await api.sshToggle(key.id, !key.agent_enabled);
      data.agent = res.agent;
      await load();
      notice = key.agent_enabled
        ? `${key.name} removed from the agent`
        : `${key.name} added to the agent`;
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function addAll() {
    error = '';
    busy = true;
    try {
      for (const key of missing) {
        await api.sshToggle(key.id, true);
      }
      await load();
      notice = 'All supported keys added to the agent';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function agentAction(action) {
    error = '';
    busy = true;
    try {
      await api.sshAgent(action);
      await load();
      notice = `Agent ${action} complete`;
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function generate() {
    error = '';
    busy = true;
    try {
      await api.sshGen({
        name: gen.name,
        kind: gen.kind,
        comment: gen.comment,
        folder: gen.folder,
        tags: splitTags(gen.tags),
        add_to_agent: gen.add_to_agent
      });
      generateOpen = false;
      gen = {
        name: '',
        kind: 'ed25519',
        comment: '',
        folder: '',
        tags: '',
        add_to_agent: false
      };
      await load();
      notice = 'SSH key generated';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function readKeyFile(event) {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    imp.private_key = await file.text();
    if (!imp.name) imp.name = file.name.replace(/^id_/, '').replace(/\.pub$/, '');
  }

  async function importKey() {
    error = '';
    busy = true;
    try {
      await api.sshImport({
        private_key: imp.private_key,
        passphrase: imp.passphrase || null,
        name: imp.name,
        comment: imp.comment,
        folder: imp.folder,
        tags: splitTags(imp.tags),
        add_to_agent: imp.add_to_agent
      });
      importOpen = false;
      imp = {
        private_key: '',
        passphrase: '',
        name: '',
        comment: '',
        folder: '',
        tags: '',
        add_to_agent: false
      };
      if (fileInput) fileInput.value = '';
      await load();
      notice = 'SSH key imported';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function splitTags(text) {
    return text
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean);
  }

  function askExport(key) {
    exportKey = key;
    exportTarget = '';
    exportOpen = true;
  }

  async function doExport(target) {
    exportOpen = false;
    if (!exportKey) return;
    error = '';
    busy = true;
    try {
      const body = { item: exportKey.id };
      if (target?.trim()) body.to = target.trim();
      await api.sshExport(body);
      await load();
      notice = target?.trim() ? `Exported to ${target.trim()}` : 'Exported to the default ~/.ssh path';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function askDelete(key) {
    deleteKey = key;
    confirmOpen = true;
  }

  async function removeKey() {
    confirmOpen = false;
    if (!deleteKey) return;
    error = '';
    try {
      await api.remove(deleteKey.id);
      await load();
      notice = `${deleteKey.name} deleted`;
    } catch (e) {
      error = e.message;
    }
  }
</script>

<PageHeader
  title="SSH keys"
  subtitle="Generate, import, and manage keys. The agent signs only while the vault is unlocked."
>
  <svelte:fragment slot="actions">
    <button class="primary" on:click={() => (generateOpen = true)}>Generate key</button>
    <button on:click={() => (importOpen = true)}>Import key</button>
  </svelte:fragment>
</PageHeader>

{#if error}<p style="color: var(--danger)">{error}</p>{/if}

<div class="card">
  <div class="row">
    <span class="vault-dot" class:off={!data.agent.running}></span>
    <strong>SSH agent</strong>
    <span class="chip">{data.agent.running ? 'running' : 'stopped'}</span>
    <span class="dim">{data.agent.identities} identit{data.agent.identities === 1 ? 'y' : 'ies'} loaded</span>
    <span style="flex: 1"></span>
    {#if data.agent.running}
      <button on:click={() => agentAction('stop')} disabled={busy}>Stop</button>
    {:else}
      <button class="primary" on:click={() => agentAction('start')} disabled={busy}>Start</button>
    {/if}
    <button on:click={() => agentAction('reload')} disabled={busy}>Reload</button>
  </div>
  <div class="row" style="margin-top: 8px">
    <code style="overflow-wrap: anywhere">{data.agent.socket || 'no socket'}</code>
    {#if data.agent.socket}
      <button class="ghost" on:click={() => copy(data.agent.socket, 'Socket path copied')}>Copy</button>
    {/if}
  </div>
  <p class="dim">
    In a shell run <code>eval $(glyx ssh agent-env)</code>, then <code>ssh-add -l</code>.
    The socket exists only while the vault is unlocked.
  </p>
</div>

{#if missing.length}
  <div class="card row">
    <span>{missing.length} supported key{missing.length === 1 ? '' : 's'} not in the agent.</span>
    <span style="flex: 1"></span>
    <button on:click={addAll} disabled={busy}>Add all Ed25519 keys</button>
  </div>
{/if}

{#if unsupported.length}
  <div class="card row">
    <span class="badge">export only</span>
    <span class="dim">
      {unsupported.length} RSA key{unsupported.length === 1 ? ' is' : 's are'} not agent-capable.
      Use Export to write {unsupported.length === 1 ? 'it' : 'them'} to disk.
    </span>
  </div>
{/if}

<div class="section-title"><h3>Keys</h3><span class="dim">{data.keys.length}</span></div>

{#if data.keys.length}
  <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Algorithm</th>
          <th>Fingerprint</th>
          <th>Agent</th>
          <th>Exports</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each data.keys as key (key.id)}
          <tr>
            <td>
              <a class="item-name" href={`/items/${key.id}`}>{key.name}</a>
              {#if key.comment}<div class="item-sub">{key.comment}</div>{/if}
            </td>
            <td><span class="badge ssh_key">{key.algorithm}</span></td>
            <td>
              <button class="ghost fingerprint" on:click={() => copy(key.fingerprint, 'Fingerprint copied')}>
                {key.fingerprint}
              </button>
            </td>
            <td>
              {#if key.agent_supported}
                <button
                  class:active={key.agent_enabled}
                  class="chip"
                  on:click={() => toggle(key)}
                  disabled={busy}
                >
                  {key.agent_enabled ? 'In agent' : 'Add to agent'}
                </button>
              {:else}
                <span class="chip">export only</span>
              {/if}
            </td>
            <td class="dim">
              {#if key.exports.length}
                {#each key.exports as target}
                  <div class="item-sub" style="overflow-wrap: anywhere">{target.target}{target.keep ? ' · keep' : ''}</div>
                {/each}
              {:else}
                —
              {/if}
            </td>
            <td class="cell-actions">
              <button on:click={() => copy(key.public, 'Public key copied')}>Copy public</button>
              <button on:click={() => askExport(key)}>Export</button>
              <button on:click={() => askDelete(key)} class="danger">Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else}
  <div class="empty">
    <strong>No SSH keys yet.</strong>
    <span>Generate a key pair or import an existing OpenSSH private key.</span>
    <div class="row">
      <button class="primary" on:click={() => (generateOpen = true)}>Generate key</button>
      <button on:click={() => (importOpen = true)}>Import key</button>
    </div>
  </div>
{/if}

<Modal bind:open={generateOpen} title="Generate SSH key" onclose={() => (generateOpen = false)}>
  <label>Name<input bind:value={gen.name} placeholder="deploy" autofocus /></label>
  <label>Algorithm
    <select bind:value={gen.kind}>
      <option value="ed25519">Ed25519 (recommended)</option>
      <option value="rsa4096">RSA 4096 (export only)</option>
    </select>
  </label>
  <label>Comment<input bind:value={gen.comment} placeholder="you@host" /></label>
  <label>Folder<input bind:value={gen.folder} placeholder="optional" /></label>
  <label>Tags<input bind:value={gen.tags} placeholder="comma, separated" /></label>
  <label class="row">
    <input type="checkbox" bind:checked={gen.add_to_agent} disabled={gen.kind !== 'ed25519'} />
    Add to agent
  </label>
  {#if gen.kind !== 'ed25519'}
    <p class="dim">RSA keys are export-only; the agent supports Ed25519.</p>
  {/if}
  <svelte:fragment slot="actions">
    <button on:click={() => (generateOpen = false)} disabled={busy}>Cancel</button>
    <button class="primary" on:click={generate} disabled={busy || !gen.name.trim()}>
      {busy ? 'Generating...' : 'Generate'}
    </button>
  </svelte:fragment>
</Modal>

<Modal bind:open={importOpen} title="Import SSH key" onclose={() => (importOpen = false)}>
  <label>Private key file
    <input bind:this={fileInput} type="file" on:change={readKeyFile} />
  </label>
  <label>Or paste the private key
    <textarea bind:value={imp.private_key} rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false"></textarea>
  </label>
  <label>Passphrase
    <input type="password" bind:value={imp.passphrase} placeholder="only for encrypted keys" />
  </label>
  <label>Name<input bind:value={imp.name} placeholder="imported key" /></label>
  <label>Comment<input bind:value={imp.comment} placeholder="optional" /></label>
  <label>Folder<input bind:value={imp.folder} placeholder="optional" /></label>
  <label>Tags<input bind:value={imp.tags} placeholder="comma, separated" /></label>
  <label class="row"><input type="checkbox" bind:checked={imp.add_to_agent} /> Add to agent (Ed25519 only)</label>
  <p class="dim">The passphrase is used only to decrypt the key and is never stored.</p>
  <svelte:fragment slot="actions">
    <button on:click={() => (importOpen = false)} disabled={busy}>Cancel</button>
    <button class="primary" on:click={importKey} disabled={busy || !imp.private_key.trim()}>
      {busy ? 'Importing...' : 'Import'}
    </button>
  </svelte:fragment>
</Modal>

<PromptDialog
  bind:open={exportOpen}
  title={exportKey ? `Export ${exportKey.name}` : 'Export SSH key'}
  label="Target path (leave empty for ~/.ssh/glyx_<name>)"
  value={exportTarget}
  confirmLabel="Export"
  busy={busy}
  onconfirm={doExport}
  onclose={() => (exportOpen = false)}
/>
<ConfirmDialog
  bind:open={confirmOpen}
  title="Delete SSH key?"
  message={deleteKey ? `Delete ${deleteKey.name}? This tombstones the item for sync safety.` : ''}
  confirmLabel="Delete"
  danger
  onconfirm={removeKey}
  onclose={() => (confirmOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
