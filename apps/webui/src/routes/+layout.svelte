<script>
  import { onMount } from 'svelte';
  import Quick from '$lib/Quick.svelte';

  let quick = false;

  onMount(() => {
    const open = () => (quick = true);
    window.addEventListener('glyx-quick', open);
    return () => window.removeEventListener('glyx-quick', open);
  });
</script>

<slot />
{#if quick}<Quick onclose={() => (quick = false)} />{/if}
