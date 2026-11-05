import { useState } from 'preact/hooks';
import changelogUrl from '../../../../CHANGELOG.md?url&no-inline';
import { loadChangelog } from '../api/client';
import { Modal } from './modal';

function inlineMarkdown(text: string) {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/).map((part, index) =>
    part.startsWith('`') && part.endsWith('`') ? <code key={index}>{part.slice(1, -1)}</code>
      : part.startsWith('**') && part.endsWith('**') ? <strong key={index}>{part.slice(2, -2)}</strong> : part);
}

export function VersionHistory({ version }: { readonly version: string }) {
  const [open, setOpen] = useState(false);
  const [notes, setNotes] = useState<string | null>();
  const close = () => setOpen(false);
  const load = () => {
    setNotes(undefined);
    void loadChangelog(changelogUrl).then(setNotes, () => setNotes(null));
  };
  return <>
    DDNS Pro · {' '}
    <button id="version-trigger" type="button" class="btn btn-sm btn-outline-secondary" aria-label={`版本历史：${version}`}
      aria-haspopup="dialog" onClick={() => { setOpen(true); if (!notes) load(); }}>{version}</button>
    {open && <Modal id="version-history-title" title="版本历史" className="version-notes" returnFocusId="version-trigger" onClose={close}>
      <button type="button" class="btn btn-sm btn-outline-secondary" onClick={close}>关闭</button>
      {notes === undefined ? <p role="status">正在读取更新日志…</p> : notes === null
        ? <p role="status">更新日志暂不可用。 <button type="button" class="btn btn-sm btn-outline-secondary" onClick={load}>重试</button></p>
        : notes.split(/^## /m).slice(1).map(section => {
          const [heading = '', ...lines] = section.trim().split(/\r?\n/);
          const [name, date] = heading.split(' - ');
          return <section key={heading}>
            <h3>{name?.replace(/^\[|\]$/g, '')} {date && <small class="text-secondary">{date}</small>}</h3>
            <ul>{lines.filter(line => line.startsWith('- ')).map(line => <li key={line}>{inlineMarkdown(line.slice(2))}</li>)}</ul>
          </section>;
        })}
    </Modal>}
  </>;
}
