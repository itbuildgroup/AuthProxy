import coerceToBase64Url from "../utils/coerceToBase64Url";
import { eddsa } from "elliptic";

const ec = new eddsa("ed25519");

const generateKeys = (passKey: string, challengeBuf: Buffer) => {
  const key = ec.keyFromSecret(passKey);
  const public_key = key.getPublic();
  const signature = key.sign(challengeBuf).toBytes();

  return {
    signature: coerceToBase64Url(signature),
    public_key: coerceToBase64Url(public_key)
  };
};

export default generateKeys;
