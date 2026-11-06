<script>
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  onMount(() => goto('/files', { replaceState: true }));
</script>

<div class="empty">
  <strong>Files &amp; Injection moved.</strong>
  <span><a href="/files">Open the new page</a></span>
</div>
