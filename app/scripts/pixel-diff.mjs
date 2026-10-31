/** Exact RGBA comparison. No ignored regions or color tolerance. */
export function comparePixels(reference, current) {
  if (reference.length !== current.length || reference.length % 4) throw new Error('RGBA sizes differ');
  const diff = new Uint8ClampedArray(reference.length);
  let changed = 0;
  let maxChannelDelta = 0;
  for (let index = 0; index < reference.length; index += 4) {
    let different = false;
    for (let channel = 0; channel < 4; channel++) {
      const delta = Math.abs(reference[index + channel] - current[index + channel]);
      if (delta) different = true;
      maxChannelDelta = Math.max(maxChannelDelta, delta);
    }
    if (different) changed++;
    diff[index] = different ? 255 : 240;
    diff[index + 1] = different ? 0 : 240;
    diff[index + 2] = different ? 80 : 240;
    diff[index + 3] = 255;
  }
  return { changed, total: reference.length / 4, maxChannelDelta, diff };
}
