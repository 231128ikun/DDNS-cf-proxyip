const themeKey = 'ddns-theme';

export function restoreTheme(): void {
  try {
    const theme = localStorage.getItem(themeKey);
    if (theme === 'light' || theme === 'dark') document.documentElement.style.colorScheme = theme;
  } catch { /* 存储不可用时跟随系统。 */ }
}

export function setTheme(theme: string): void {
  document.documentElement.style.colorScheme = theme === 'system' ? '' : theme;
  try { localStorage.setItem(themeKey, theme); } catch { /* 当前页面仍可切换外观。 */ }
}
