<script>
  export let title = '';
  export let subtitle = '';
</script>

<div class="page-header">
  <div class="page-header-text">
    <h1>{title}</h1>
    {#if subtitle}<p>{subtitle}</p>{/if}
  </div>
  <div class="page-actions">
    <slot name="actions" />
  </div>
</div>
