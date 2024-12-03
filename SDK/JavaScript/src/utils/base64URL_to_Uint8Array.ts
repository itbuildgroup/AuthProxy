const base64URL_to_Uint8Array = (str: string) =>
  Uint8Array.from(
    Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString(
      "latin1"
    ),
    (c) => c.charCodeAt(0)
  );

export default base64URL_to_Uint8Array;
