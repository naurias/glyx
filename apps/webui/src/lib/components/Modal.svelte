<script>
  export let open = false;
  export let title = '';
  export let onclose = () => {};

  function onkey(e) {
    if (open && e.key === 'Escape') onclose();
  }
</script>

<svelte:window on:keydown={onkey} />

{#if open}
  <div class="modal-backdrop" on:click={onclose} role="presentation">
    <div
      class="modal"
      on:click|stopPropagation
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      {#if title}<h3>{title}</h3>{/if}
      <slot />
      {#if $$slots.actions}
        <div class="modal-actions">
          <slot name="actions" />
        </div>
      {/if}
    </div>
  </div>
{/if}
