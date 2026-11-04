import { useState } from 'preact/hooks';
import changelog from '../../../../CHANGELOG.md?raw';

const releases = changelog.split(/^## /m).slice(1).map(section => ({
  version: section.match(/^\[([^\]]+)\]/)?.[1] ?? '',
  notes: section.split('\n').filter(line => line.startsWith('- ')).map(line => line.slice(2)),
}));

export function VersionHistory({ version }: { readonly version: string }) {
  const [open, setOpen] = useState(false);
  return <div class="version-history" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}
    onFocusIn={() => setOpen(true)} onFocusOut={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false); }}>
    DDNS Pro · {' '}
    <button type="button" class="btn btn-sm btn-outline-secondary" aria-label="版本更新历史" aria-expanded={open} aria-controls="version-notes"
      onClick={() => setOpen(true)} onKeyDown={event => { if (event.key === 'Escape') setOpen(false); }}>{version}</button>
    <div id="version-notes" class="version-notes card p-4" role="region" aria-label="版本更新历史" hidden={!open}>
      <button type="button" class="btn btn-sm btn-outline-secondary" aria-label="关闭更新历史" onClick={() => setOpen(false)}>关闭</button>
      {releases.map(release => <section key={release.version}><strong>{release.version}</strong><ul>{release.notes.map(note => <li key={note}>{note}</li>)}</ul></section>)}
    </div>
  </div>;
}
