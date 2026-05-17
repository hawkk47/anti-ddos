<script lang="ts">
  import { toasts, dismissToast } from '../lib/stores';
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each $toasts as t (t.id)}
    <div class="toast {t.kind}">
      <span class="msg">{t.text}</span>
      <button class="x" on:click={() => dismissToast(t.id)} title="dismiss">×</button>
    </div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed;
    bottom: 12px;
    right: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    z-index: 1000;
    max-width: 360px;
    pointer-events: none;
  }
  .toast {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 8px 5px 10px;
    border: 1px solid var(--border-strong);
    border-left-width: 3px;
    background: var(--bg-elev);
    color: var(--text);
    font-size: 12px;
    border-radius: 3px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    animation: slide-in 160ms ease-out;
  }
  .toast.ok { border-left-color: var(--ok); }
  .toast.err { border-left-color: var(--err); background: var(--danger-bg); }
  .toast.warn { border-left-color: var(--warn); }
  .toast.info { border-left-color: var(--accent); }
  .msg { flex: 1; word-break: break-word; }
  .x {
    border: none;
    background: transparent;
    color: var(--text-faint);
    font-size: 16px;
    line-height: 1;
    padding: 0 4px;
    cursor: pointer;
  }
  .x:hover { color: var(--text); }
  @keyframes slide-in {
    from { transform: translateX(8px); opacity: 0; }
    to   { transform: translateX(0); opacity: 1; }
  }
  @media (prefers-reduced-motion: reduce) {
    .toast { animation: none; }
  }
</style>
