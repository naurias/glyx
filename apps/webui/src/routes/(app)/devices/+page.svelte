<script>
  import { api } from '$lib/api.js';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/PageHeader.svelte';
  import PromptDialog from '$lib/components/PromptDialog.svelte';
  import Toast from '$lib/components/Toast.svelte';

  let devices = [];
  let error = '';
  let notice = '';

  let promptOpen = false;
  let promptValue = '';
  let promptDevice = null;

  async function load() {
    error = '';
    try {
      devices = (await api.devices()).devices || [];
    } catch (e) {
      error = e.message;
    }
  }

  onMount(load);

  function rename(device) {
    promptDevice = device;
    promptValue = device.label;
    promptOpen = true;
  }

  async function saveLabel(label) {
    promptOpen = false;
    if (!promptDevice || !label || label === promptDevice.label) return;
    error = '';
    try {
      await api.labelDevice(promptDevice.id, label);
      notice = 'Device label saved';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  function seen(ms) {
    return ms ? new Date(ms).toLocaleString() : 'never';
  }
</script>

<PageHeader title="Devices" subtitle="Last seen is the newest write activity in this vault, not online presence. Labels stay on this device." />

{#if error}<p style="color: var(--danger)">{error}</p>{/if}

{#each devices as device (device.id)}
  <div class="card row">
    <strong>{device.label}</strong>
    {#if device.current}<span class="dim">current</span>{/if}
    <span class="dim">{device.id}</span>
    <span style="flex: 1"></span>
    <span class="dim">{seen(device.last_seen_ms)}</span>
    <button on:click={() => rename(device)}>Rename</button>
  </div>
{/each}
{#if !devices.length}<div class="empty"><strong>No devices observed yet.</strong></div>{/if}

<PromptDialog
  bind:open={promptOpen}
  title="Rename device"
  label="Label"
  value={promptValue}
  confirmLabel="Save label"
  onconfirm={saveLabel}
  onclose={() => (promptOpen = false)}
/>
<Toast message={notice} onclose={() => (notice = '')} />
