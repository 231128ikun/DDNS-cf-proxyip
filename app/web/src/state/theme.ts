const themeKey = 'ddns-theme';
type Theme = 'system' | 'light' | 'dark';

export function currentTheme(): Theme {
  const theme = document.documentElement.style.colorScheme;
  return theme === 'light dark' ? 'system' : theme === 'dark' ? 'dark' : 'light';
}

function applyTheme(theme: Theme): void {
  document.documentElement.style.colorScheme = theme === 'system' ? 'light dark' : theme;
}

export function restoreTheme(): void {
  try {
    const theme = localStorage.getItem(themeKey);
    if (theme === 'light' || theme === 'dark' || theme === 'system') applyTheme(theme);
  } catch { /* 存储不可用时使用默认浅色。 */ }
}

export function cycleTheme(current: Theme): Theme {
  const theme = current === 'light' ? 'dark' : current === 'dark' ? 'system' : 'light';
  applyTheme(theme);
  try { localStorage.setItem(themeKey, theme); } catch { /* 当前页面仍可切换外观。 */ }
  return theme;
}
