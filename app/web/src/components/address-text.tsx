export function AddressText({ value }: { readonly value: string }) {
  const parts = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(value);
  return <code class="syntax-address">{parts
    ? <>{parts[1]}<span class="syntax-number">:{parts[2]}</span></>
    : value}</code>;
}
