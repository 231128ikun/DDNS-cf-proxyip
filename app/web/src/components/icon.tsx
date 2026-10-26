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
  | 'plus'
  | 'refresh'
  | 'save'
  | 'search'
  | 'settings'
  | 'stop'
  | 'trash'
  | 'up'
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
  plus: '➕',
  refresh: '🔄',
  save: '💾',
  search: '🔎',
  settings: '⚙️',
  stop: '⏹',
  trash: '🗑️',
  up: '↑',
  wrench: '🔧',
};

export function Icon({ name }: { readonly name: IconName }) {
  return <span class="ui-icon" aria-hidden="true">{ICONS[name]}</span>;
}
