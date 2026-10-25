<script>
  import '../app.css';
  import { onMount } from 'svelte';
  import Quick from '$lib/Quick.svelte';
  import { api } from '$lib/api.js';

  let quick = false;

  onMount(() => {
    const open = () => (quick = true);
    const lock = async () => {
      try {
        await api.lock();
        window.location.href = '/';
      } catch (e) {
        console.warn('glyx lock failed', e);
      }
    };
    window.addEventListener('glyx-quick', open);
    window.addEventListener('glyx-lock', lock);
    return () => {
      window.removeEventListener('glyx-quick', open);
      window.removeEventListener('glyx-lock', lock);
    };
  });
</script>

<slot />
{#if quick}<Quick onclose={() => (quick = false)} />{/if}
