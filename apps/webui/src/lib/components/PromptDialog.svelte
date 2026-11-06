<script>
  import Modal from './Modal.svelte';

  export let open = false;
  export let title = '';
  export let label = '';
  export let value = '';
  export let type = 'text';
  export let placeholder = '';
  export let confirmLabel = 'Save';
  export let busy = false;
  export let error = '';
  export let onconfirm = () => {};
  export let onclose = () => {};

  let local = value;

  $: if (open) local = value;

  function submit() {
    if (!busy) onconfirm(local);
  }
</script>

<Modal {open} {title} {onclose}>
  <form on:submit|preventDefault={submit}>
    {#if label}<label>{label}<input {type} bind:value={local} {placeholder} autofocus /></label>{/if}
    {#if error}<p class="modal-error">{error}</p>{/if}
    <div class="modal-actions">
      <button type="button" on:click={onclose}>Cancel</button>
      <button type="submit" class="primary" disabled={busy}>{busy ? 'Working...' : confirmLabel}</button>
    </div>
  </form>
</Modal>
