<script>
  import Modal from './Modal.svelte';

  export let open = false;
  export let title = '';
  export let message = '';
  export let confirmLabel = 'Confirm';
  export let danger = false;
  export let busy = false;
  export let onconfirm = () => {};
  export let onclose = () => {};
</script>

<Modal {open} {title} {onclose}>
  {#if message}<p class="dim">{message}</p>{/if}
  <slot />
  <div class="modal-actions">
    <button on:click={onclose} disabled={busy}>Cancel</button>
    <button class:danger class="primary" on:click={onconfirm} disabled={busy}>
      {busy ? 'Working...' : confirmLabel}
    </button>
  </div>
</Modal>
