const coerceToBase64Url = (thing) => {
  // Convert Array or ArrayBuffer to Uint8Array
  if (Array.isArray(thing)) {
    thing = Uint8Array.from(thing);
  }

  if (thing instanceof ArrayBuffer) {
    thing = new Uint8Array(thing);
  }

  // Uint8Array to base64
  if (thing instanceof Uint8Array) {
    let base64;

    if (typeof Buffer !== 'undefined') {
      // Node.js environment
      base64 = Buffer.from(thing).toString('base64');
    } else if (typeof TextEncoder !== 'undefined') {
      // Browser environment with TextEncoder
      const binary = Array.from(thing)
        .map((byte) => String.fromCharCode(byte))
        .join('');
      base64 = btoa(binary);
    } else {
      throw new Error('No suitable base64 encoding method found.');
    }

    thing = base64;
  }

  if (typeof thing !== 'string') {
    throw new Error('Could not coerce to string');
  }

  // Convert base64 to base64url
  thing = thing.replace(/\+/g, '-').replace(/\//g, '_');

  return thing;
};

export default coerceToBase64Url;
