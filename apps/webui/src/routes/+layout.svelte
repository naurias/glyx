<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { totpCapture, watchOtpauthLinks } from '$lib/totp-capture.js';
  import '../app.css';

  onMount(() =>
    watchOtpauthLinks((uri) => {
      totpCapture.set(uri);
      goto('/add');
    })
  );
</script>

<slot />
