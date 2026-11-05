export type IconName =
  | 'activity'
  | 'antenna'
  | 'compass'
  | 'dashboard'
  | 'database'
  | 'download'
  | 'upload'
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

export function Icon({ name }: { readonly name: IconName }) {
  return <svg class="ui-icon" width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><use href={`/icons.svg#${name}`} /></svg>;
}
