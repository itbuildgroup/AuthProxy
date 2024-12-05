import base64ToUint8Array from "./utils/base64ToUint8Array";
import generateKeys from "./helpers/generateKeys";
import {
    apiGetInfo,
    apiLogin,
    apiLoginLog,
    apiLoginOptions,
    apiLogout,
    apiRegisterOptions,
    RegisterKey,
    ResetPassword
} from "./api";
import {
    ServerInfo,
    LoginInfo,
    ErrorObject,
    UserLoginLog,
    AuthOptions
} from "./api/model";
import { setFetchSessionId } from "./api/api-request";
import formatAsNumber from "./utils/formatAsNumber";
import getRandomText from "./utils/getRandomText";
import genSha256 from "./utils/genSha256";

export class AuthProxyClient {
    private sessionId: string | null = null;

    /**
     * Function to return AuthProxyClient sessionId
     * To initialize new session execute {@link SignInUserKey}
     * @returns sessionId string if session exists
     * @returns `null` if session not found
     */
    public GetSessionId = (): string | null => this.sessionId;

    /**
     * Initialize new session using userKey
     * @param userKey User's key
     * @returns string result on success
     * @returns `null` on error
     */
    public async SignInUserKey(userKey: string): Promise<string | null> {
        if (!userKey.trim()) return null;

        const loginOptionResponse = await apiLoginOptions();

        if (!loginOptionResponse.result) return null;

        const authOptions = loginOptionResponse.result;

        const challengeBuf = base64ToUint8Array(authOptions.challenge) as Buffer;

        const { signature, public_key } = generateKeys(userKey, challengeBuf);

        const data: LoginInfo = {
            challenge_id: authOptions.challenge_id,
            credential: null,
            public_key,
            signature
        };

        const loginResponse = await apiLogin(data);

        if (loginResponse.result && loginResponse.result !== "Failure") {
            let sid = loginResponse.headers['set-cookie'].match(/sid=([^;]+)/)[1];
            this.sessionId = sid;
            setFetchSessionId(sid);

            return loginResponse.result;
        }

        return null;
    };

    /**
     * Get server info
     * @returns object of {@link ServerInfo} on success
     * @returns object of {@link ErrorObject} on error
     */
    public async GetInfo(): Promise<ServerInfo | ErrorObject> {
        const response = await apiGetInfo();

        if (response.result || !response.error) {
            return response.result;
        };

        return response.error;
    }

    /**
     * Get last 100 login operations
     * @returns array of {@link UserLoginLog} on success
     * @returns object of {@link ErrorObject} on error
     */
    public async GetLoginLog(): Promise<UserLoginLog[] | ErrorObject> {
        const response = await apiLoginLog();

        if (response.result || !response.error) {
            return response.result;
        };

        return response.error;
    }

    /**
     * Call password reset, sends email code
     * @param phone User's phone number
     * @returns status string on success
     * @returns `null` on error
     */
    async ResetPassword(phone: string): Promise<string | null> {
        if (!formatAsNumber(phone.trim())) return null;

        const response = await ResetPassword(phone);

        if (response.result || response.result !== "Failure") {
            return response.result;
        };

        return null;
    };

    /**
     * Initialize new key registration
     * @param code Code from email (unauthorized)
     * @param sid User's session id (authorized)
     * @returns object of {@link AuthOptions} on success
     * @returns `null` on error
     */
    async InitializeNewKey(code: string): Promise<AuthOptions | null> {
        if (!code.trim()) return null;

        const response = await apiRegisterOptions(code);

        if (response.result) {
            return response.result;
        };

        return null;
    };

    /**
     * Creates a user key and registers it in the system
     * @param otp one time password from {@link InitializeNewKey} call
     * @param options Authorization options, returned from {@link InitializeNewKey}
     * @returns User's key to authorize via {@link SignInUserKey}
     * @returns object of {@link ErrorObject} on error
     */
    async CreateUserKey(otp: string, options: AuthOptions): Promise<string | ErrorObject> {
        if (!otp.trim() && otp.length !== 6) return null;

        const challengeBuf = base64ToUint8Array(options.fido2_options.challenge) as Buffer;

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

    /**
     * Close current session function
     * @returns string result on success
     * @returns `null` on error
     */
    public async Logout(): Promise<string | null> {
        const response = await apiLogout();

        if (response.result || !response.error) {
            return response.result;
        };

        return null;
    }
}
