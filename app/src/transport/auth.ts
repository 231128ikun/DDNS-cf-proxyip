export function isAuthorized(request: Request, expectedKey: string | undefined): boolean {
  const expected = expectedKey?.trim();
  if (!expected) return true;

  const authorization = request.headers.get('authorization') ?? '';
  const bearer = authorization.toLowerCase().startsWith('bearer ') ? authorization.slice(7).trim() : '';
  const headerKey = request.headers.get('x-auth-key')?.trim() ?? '';
  const queryKey = new URL(request.url).searchParams.get('key')?.trim() ?? '';
  return [bearer, headerKey, queryKey].some((candidate) => candidate && constantTimeEqual(candidate, expected));
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let diff = leftBytes.length ^ rightBytes.length;

  for (let index = 0; index < length; index += 1) {
    diff |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return diff === 0;
}