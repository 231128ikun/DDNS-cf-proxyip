export type RecordMode = 'A' | 'TXT';

export function RecordBadge({ mode }: { readonly mode: RecordMode }) {
  return (
    <span class={`record-badge ${mode === 'TXT' ? 'record-badge-txt' : 'record-badge-a'}`} title={mode === 'TXT' ? 'TXT' : 'A/AAAA'}>
      {mode === 'TXT' ? 'T' : 'A'}
    </span>
  );
}
