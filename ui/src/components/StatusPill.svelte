<script lang="ts">
  export let kind: 'ok' | 'warn' | 'err' | 'dim';
  export let label: string;
</script>

<span class="badge {kind}">{label}</span>
