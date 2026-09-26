export type IconName =
  | 'activity'
  | 'dashboard'
  | 'database'
  | 'download'
  | 'globe'
  | 'help'
  | 'plus'
  | 'refresh'
  | 'save'
  | 'search'
  | 'settings';

/** 所有图标共用一条描边路径，避免为每个 SVG 子节点重复创建属性对象。 */
const ICONS: Record<IconName, string> = {
  activity: 'M3 12h4l2.2-6 4.2 12 2.2-6H21',
  dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  database: 'M5 5.5a7 3 0 1 0 14 0a7 3 0 1 0-14 0 M5 5.5v6c0 1.66 3.13 3 7 3s7-1.34 7-3v-6 M5 11.5v6c0 1.66 3.13 3 7 3s7-1.34 7-3v-6',
  download: 'M12 3v12 M7.5 10.5l4.5 4.5 4.5-4.5 M5 20h14',
  globe: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0 M3 12h18 M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9S9.5 5.5 12 3Z',
  help: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0 M9.6 9a2.5 2.5 0 1 1 3.3 2.36c-.9.34-1.4.9-1.4 1.64v.5 M12 17h.01',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M20 11a8 8 0 1 0-2.35 5.65 M20 5v6h-6',
  save: 'M5 4h11l3 3v13H5z M8 4v6h8V4 M8 20v-6h8v6',
  search: 'M4.5 11a6.5 6.5 0 1 0 13 0a6.5 6.5 0 1 0-13 0 M16 16l4.5 4.5',
  settings: 'M4 6h16M4 12h16M4 18h16 M7 6a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M13 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M6 18a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
};

export function Icon({ name }: { readonly name: IconName }) {
  return (
    <svg
      class="ui-icon"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={ICONS[name]} />
    </svg>
  );
}
