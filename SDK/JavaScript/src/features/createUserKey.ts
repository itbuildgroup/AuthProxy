import generateKeys from "../helpers/generateKeys";
import { signInUserKey } from "./signInUserKey";
import { AuthOptions, LoginInfo } from "../api/model";
import { ErrorObject } from "../api/model";
import base64URL_to_Uint8Array from "../utils/base64URL_to_Uint8Array";
import getRandomText from "../utils/getRandomText";
import genSha256 from "../utils/genSha256";
import { RegisterKey } from "../api";
import { initializeNewKey } from "./initializeNewKey";

/**
 * Creates a user key and registers it in the system
 * @param otp one time password from {@link initializeNewKey} call
 * @param options Authorization options, returned from {@link initializeNewKey}
 * @returns User's key to authorize via {@link signInUserKey}
 * @returns object of {@link ErrorObject} on error
 */
export async function createUserKey(otp: string, options: AuthOptions): Promise<string | ErrorObject> {
    if (!otp.trim() && otp.length !== 6) return null;

    const challengeBuf = base64URL_to_Uint8Array(options.fido2_options.challenge) as Buffer;

    const randomText = getRandomText();
    const passKey = genSha256(randomText);
    const { signature, public_key } = generateKeys(passKey, challengeBuf);

    const data: LoginInfo = {
        challenge_id: options.challenge_id,
        code: otp.trim(),
        public_key,
        signature
    };

    const response = await RegisterKey(data);

    if (response.result && response.result !== "Failure") {
        return passKey;
    }

    return response.error;
};
