const themeKey = 'ddns-theme';
type Theme = 'system' | 'light' | 'dark';

export function currentTheme(): Theme {
  const theme = document.documentElement.style.colorScheme;
  return theme === 'light' || theme === 'dark' ? theme : 'system';
}

export function restoreTheme(): void {
  try {
    const theme = localStorage.getItem(themeKey);
    if (theme === 'light' || theme === 'dark') document.documentElement.style.colorScheme = theme;
  } catch { /* 存储不可用时跟随系统。 */ }
}

export function cycleTheme(current: Theme): Theme {
  const system = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  const opposite = system === 'dark' ? 'light' : 'dark';
  const theme = current === 'system' ? opposite : current === opposite ? system : 'system';
  document.documentElement.style.colorScheme = theme === 'system' ? '' : theme;
  try { localStorage.setItem(themeKey, theme); } catch { /* 当前页面仍可切换外观。 */ }
  return theme;
}
