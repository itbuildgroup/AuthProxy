
import base64URL_to_Uint8Array from "../utils/base64URL_to_Uint8Array";
import generateKeys from "../helpers/generateKeys";
import { createUserKey } from "./createUserKey";
import { LoginInfo } from "../api/model";
import { apiLogin, apiLoginOptions } from "../api";

/**
 * Authorize user via user key
 * @param userKey User's user key from {@link createUserKey}
 * @returns set-cookie header string on success
 * @returns `null` on error
 */
export async function signInUserKey(): Promise<string | null> {
  const userKey = process.env['USER_KEY'];
  
  if (!userKey.trim()) return null;

  const loginOptionResponse = await apiLoginOptions();

  if (!loginOptionResponse.result) return null;
  
  const opt = loginOptionResponse.result;

  const challengeBuf = base64URL_to_Uint8Array(opt.challenge) as Buffer;

  const { signature, public_key } = generateKeys(userKey, challengeBuf);

  const data: LoginInfo = {
    challenge_id: opt.challenge_id,
    credential: null,
    public_key,
    signature
  };

  const loginResponse = await apiLogin(data);

  if (loginResponse.result && loginResponse.result !== "Failure") {
    return loginResponse.headers['set-cookie'].match(/sid=([^;]+)/)[1];
  }

  return null;
};
