export function parseTxtAddresses(content: string): readonly string[] {
  const unquoted = content.trim().replace(/^"|"$/g, '');
  if (!unquoted) return [];
  return [...new Set(unquoted.split(',').map((item) => item.trim()).filter(Boolean))];
}

export function formatTxtAddresses(addresses: readonly string[]): string {
  return `"${[...new Set(addresses)].join(',')}"`;
}
