export type RecordMode = 'A' | 'TXT';

/** A/AAAA 与 TXT 的记录类型徽标；同一语义只保留这一份展示实现。 */
export function RecordBadge({ mode }: { readonly mode: RecordMode }) {
  return (
    <span class={`record-badge ${mode === 'TXT' ? 'record-badge-txt' : 'record-badge-a'}`}>
      {mode}
    </span>
  );
}