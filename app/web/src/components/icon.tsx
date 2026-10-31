export type IconName =
  | 'activity'
  | 'antenna'
  | 'compass'
  | 'dashboard'
  | 'database'
  | 'download'
  | 'folder'
  | 'globe'
  | 'help'
  | 'link'
  | 'sort'
  | 'plus'
  | 'pencil'
  | 'broom'
  | 'recycle'
  | 'refresh'
  | 'save'
  | 'search'
  | 'settings'
  | 'stop'
  | 'trash'
  | 'wrench';

/** 保留 DDNS Pro 的原有图标语言，名称与显示字符只维护在这里。 */
const ICONS: Record<IconName, string> = {
  activity: '⚡',
  antenna: '📡',
  compass: '🧭',
  dashboard: '📊',
  database: '📦',
  download: '🌐',
  folder: '📂',
  globe: '🌐',
  help: '?',
  link: '🔗',
  sort: '↕️',
  plus: '➕',
  pencil: '✏️',
  broom: '🧹',
  recycle: '♻️',
  refresh: '🔄',
  save: '💾',
  search: '🔎',
  settings: '⚙️',
  stop: '🛑',
  trash: '🗑️',
  wrench: '🔧',
};

export function Icon({ name }: { readonly name: IconName }) {
  return <span class="ui-icon" aria-hidden="true">{iconText(name)}</span>;
}

/** 连续文字中的 emoji 保持同一个文本排版上下文，避免小字号下被分段取整。 */
export function iconText(name: IconName): string { return ICONS[name]; }
