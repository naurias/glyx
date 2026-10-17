<script>
  import { api } from './api.js';
  import { onMount } from 'svelte';

  export let onclose = () => {};

  let q = '';
  let items = [];
  let selected = 0;
  let error = '';
  let status = '';
  let input;

  onMount(async () => {
    try {
      items = await api.items();
    } catch (e) {
      error = e.message;
    }
    input?.focus();
  });

  $: filtered = items
    .filter(
      (i) =>
        !q ||
        i.name.toLowerCase().includes(q.toLowerCase()) ||
        i.type.includes(q.toLowerCase())
    )
    .slice(0, 30);

  async function choose(item) {
    error = '';
    try {
      await api.fill(item.id, 'password');
      status = `${item.name}: password copied (clears in 15s)`;
      setTimeout(onclose, 700);
    } catch (e) {
      error = e.message;
    }
  }

  function onkey(e) {
    if (e.key === 'Escape') {
      onclose();
    } else if (e.key === 'ArrowDown') {
      selected = Math.min(selected + 1, Math.max(filtered.length - 1, 0));
      e.preventDefault();
    } else if (e.key === 'ArrowUp') {
      selected = Math.max(selected - 1, 0);
      e.preventDefault();
    } else if (e.key === 'Enter' && filtered[selected]) {
      choose(filtered[selected]);
    }
  }
</script>

<div class="quick-backdrop" on:click={onclose} role="presentation">
  <div class="quick" on:click|stopPropagation role="presentation">
    <input
      bind:this={input}
      bind:value={q}
      on:keydown={onkey}
      placeholder="Search and copy password..."
    />
    {#if error}<p style="color: var(--danger)">{error}</p>{/if}
    {#if status}<p class="dim">{status}</p>{/if}
    {#each filtered as it, i}
      <div
        class="row quick-item"
        class:active={i === selected}
        on:click={() => choose(it)}
        role="presentation"
      >
        <span>{it.name}</span>
        <span style="flex: 1"></span>
        <span class="dim">{it.type}</span>
      </div>
    {/each}
    {#if !filtered.length}<p class="dim">No matching items.</p>{/if}
  </div>
</div>

<style>
  .quick-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding-top: 10vh;
    z-index: 50;
  }
  .quick {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 12px;
    width: min(520px, 90vw);
  }
  .quick input {
    width: 100%;
  }
  .quick-item {
    padding: 8px;
    border-radius: 8px;
    cursor: pointer;
  }
  .quick-item.active {
    background: var(--line);
  }
</style>
