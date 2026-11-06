<script>
  import { onDestroy } from 'svelte';

  export let message = '';
  export let onclose = () => {};

  let timer;

  $: if (message) {
    clearTimeout(timer);
    timer = setTimeout(onclose, 4500);
  }

  onDestroy(() => clearTimeout(timer));
</script>

{#if message}
  <div class="toast" role="status">{message}</div>
{/if}
