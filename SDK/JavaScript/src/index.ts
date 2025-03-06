import base64ToUint8Array from "./utils/base64ToUint8Array";
import generateKeys from "./helpers/generateKeys";
import {
  ServerInfo,
  LoginInfo,
  UserLoginLog,
  AuthOptions,
  ApiResponse,
  ApiResponseExt
} from "./model";
import formatAsNumber from "./utils/formatAsNumber";
import getRandomText from "./utils/getRandomText";
import genSha256 from "./utils/genSha256";
import { EventSource } from "eventsource";
import { v4 as uuidV4 } from "uuid";
import * as fs from 'fs';
import * as path from 'path';
import { version } from '../package.json';

export * from './model';

export class AuthProxyClient {
  public readonly BaseUrl: string = null;

  private userKey: string = null;
  private esLink: EventSource = null;
  private isConnected: boolean = false;
  private isConnectedES: boolean = false;
  private sessionId: string | null = null;
  private deviceGuid: string | null = null;

  constructor(userKey: string, baseUrl: string) {
    this.BaseUrl = baseUrl;
    this.userKey = userKey;
  }

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
   * @returns string result `Success`/`Failure`
   */
  public async SignInUserKey(userKey: string): Promise<ApiResponse<string>> {
    if (!userKey.trim()) {
      return this.validationErrorResponse("User key must be not empty");
    }

    const loginOptionResponse = await this.ApiRequest<AuthOptions>(
      "auth/v1/login_options",
      {
        method: "GET",
      }
    );

    if (!loginOptionResponse.result) {
      return {
        result: null,
        error: loginOptionResponse.error
      };
    }

    const authOptions = loginOptionResponse.result;

    const challengeBuf = base64ToUint8Array(authOptions.challenge) as Buffer;

    const { signature, public_key } = generateKeys(userKey, challengeBuf);

    const data: LoginInfo = {
      challenge_id: authOptions.challenge_id,
      credential: null,
      public_key,
      signature
    };

    const loginResponse = await this.ApiRequest<string>(
      "auth/v1/login",
      {
        method: "POST",
        body: JSON.stringify(data),
        headers: {
          resolution: 'console',
          device_guid: this.getDeviceGuid(),
          "User-Agent": `AuthProxy SDK v.${version}`
        }
      }
    );

    if (loginResponse.result && loginResponse.result !== "Failure") {
      this.sessionId = loginResponse.headers['set-cookie'].match(/sid=([^;]+)/)[1];
      this.isConnected = true;
    }

    return loginResponse;
  };

  /**
   * Create new session
   * @param force create session even if session is active
   * @returns `true` on success
   * @returns `false` on error
   */
  public async Connect(force: boolean = false): Promise<boolean> {
    if (!force && this.isConnected) {
      return this.isConnected;
    }

    const response = await this.SignInUserKey(this.userKey);

    return !response.error && response.result !== 'Failure';
  }

  /**
   * Get server info
   * @returns object of {@link ServerInfo}
   */
  public async GetInfo(): Promise<ApiResponse<ServerInfo>> {
    return await this.ApiRequest<ServerInfo>("auth/v1/get_info", {
      method: "GET"
    });
  }

  /**
   * Get last 100 login operations
   * @returns array of {@link UserLoginLog} objects
   */
  public async GetLoginLog(): Promise<ApiResponse<UserLoginLog[]>> {
    return await this.ApiRequest<UserLoginLog[]>("auth/v1/login_log", {
      method: "GET"
    });
  }

  /**
   * Call password reset, sends email code
   * @param phone User's phone number
   * @returns string result `Success`/`Failure`
   */
  public async ResetPassword(phone: string): Promise<ApiResponse<string>> {
    if (!formatAsNumber(phone.trim())) {
      return this.validationErrorResponse("Phone must be not empty");
    }

    return await this.ApiRequest<string>(
      `auth/v1/reset_password?phone=${phone}`,
      {
        method: "GET",
        headers: {
          resolution: 'console',
          device_guid: this.getDeviceGuid(),
          "User-Agent": `AuthProxy SDK v.${version}`
        }
      }
    );
  };

  /**
   * Initialize new key registration
   * @param code Code from email (unauthorized)
   * @param sid User's session id (authorized)
   * @returns object of {@link AuthOptions}
   */
  public async InitializeNewKey(emailCode: string): Promise<ApiResponse<AuthOptions>> {
    if (!emailCode.trim()) {
      return this.validationErrorResponse("Email code must be not empty");
    }

    return await this.ApiRequest<AuthOptions>(
      `auth/v1/register_options${emailCode ? `?code=${emailCode}` : ""}`,
      { method: "GET" }
    );
  };

  /**
   * Creates a user key and registers it in the system
   * @param otp one time password from {@link InitializeNewKey} call
   * @param options Authorization options, returned from {@link InitializeNewKey}
   * @returns User's passKey string
   */
  public async CreateUserKey(otp: string, options: AuthOptions): Promise<ApiResponse<string>> {
    if (!otp.trim() && otp.length !== 6) {
      return this.validationErrorResponse("OTP must be not empty");
    }

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

    const response = await this.ApiRequest<string>(
      "auth/v1/register_key",
      {
        method: "POST",
        body: JSON.stringify(data)
      }
    );

    if (response.result && response.result !== "Failure") {
      return {
        result: passKey,
        error: null
      };
    }

    return response;
  };

  /**
   * Subscribe app to server EventSource
   * @returns `true` on success
   * @returns `false` on error
   */
  public Subscribe(handleMessage: (object: unknown) => Promise<void> = async () => { }): boolean {
    if (this.isConnectedES || !this.sessionId) {
      return false;
    }

    try {
      this.esLink = new EventSource(`${this.BaseUrl}auth/v1/Subscribe`, {
        fetch: (input, init) =>
          fetch(input, {
            ...init,
            headers: {
              ...init.headers,
              Cookie: `sid=${this.sessionId}`
            }
          })
      });

      this.esLink.onmessage = async (event: MessageEvent<{ data: unknown }>) => {
        var message = this.getMessageFromEvent(event.data);
        await handleMessage(message);
      };

      this.esLink.onerror = (error: unknown) => {
        console.error("EventSource error:", error);
      };

      this.isConnectedES = true;
    } catch (error) {
      console.error("EventSource error:", error);
      return false;
    }

    return true;
  }

  /**
   * Unsubscribes from EventSource
   * @returns `true` on success
   * @returns `false` on error
   */
  public Unsubscribe(): boolean {
    if (!this.isConnectedES) {
      return false;
    }

    this.esLink.close();
    this.isConnectedES = false;

    return true;
  }

  /**
   * Close current session function
   * @returns string result `Success`/`Failure`
   */
  public async Logout(): Promise<ApiResponse<string>> {
    return await this.ApiRequest<string>(`auth/v1/logout`, {
      method: "GET"
    });
  }

  private validationErrorResponse<T>(message: string): ApiResponse<T> {
    return {
      result: null,
      error: {
        code: -1,
        message
      }
    };
  }

  private getDeviceGuid(): string {
    // Return deviceGuid if exists
    if (this.deviceGuid) {
      return this.deviceGuid;
    }

    const configPath = path.join(process.cwd(), 'authProxyConfig.json');

    // Try to get deviceGuid from authProxyConfig.json
    let configData: { deviceGuid?: string } = {};

    try {
      if (fs.existsSync(configPath)) {
        const fileContent = fs.readFileSync(configPath, 'utf-8');
        configData = JSON.parse(fileContent);
      }
    } catch (error) {
      console.error('Error reading authProxyConfig.json:', error);
    }

    // Return deviceGuid if found in file
    if (configData.deviceGuid) {
      this.deviceGuid = configData.deviceGuid;
      return this.deviceGuid;
    }

    // Generate new deviceGuid
    function getRandomUint8Array(): Uint8Array {
      const arr = new Uint8Array(16);

      if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
        crypto.getRandomValues(arr);
      } else {
        for (let i = 0; i < 16; i++) {
          arr[i] = Math.floor(Math.random() * 256);
        }
      }

      return arr;
    }

    this.deviceGuid = uuidV4({
      random: getRandomUint8Array()
    });

    // Save deviceGuid to authProxyConfig.json
    try {
      const newConfigData = { ...configData, deviceGuid: this.deviceGuid };
      fs.writeFileSync(configPath, JSON.stringify(newConfigData, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error trying create authProxyConfig.json file:', error);
    }

    return this.deviceGuid;
  }

  private getMessageFromEvent(message: unknown) {
    let jsonValue: unknown = null;
    console.log("Message received:", message);

    if (typeof message !== "string") {
      console.log(message);
      return;
    }

    try {
      jsonValue = JSON.parse(message);
    } catch (error) {
      console.error("Error parsing message:", error);
    }

    return jsonValue;
  }

  private async ApiRequest<T>(url: string, init?: RequestInit): Promise<ApiResponseExt<T>> {
    const headers: Record<string, string> = {};
    const defaultHeaders: Record<string, string> = {
      Accept: "application/json",
      "Content-Type": "application/json"
    };

    try {
      const request = fetch(this.BaseUrl + url, {
        credentials: "include",
        ...init,
        headers: {
          ...defaultHeaders,
          ...init.headers,
          ...(this.sessionId ? { Cookie: `sid=${this.sessionId}` } : {})
        }
      });

      var response = await request;

      // Try to reconnect on 401
      if (response.status === 401) {
        this.isConnected = false;
        this.Connect(true);

        response = await request;
      }

      if (response.ok) {
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });

        return {
          ...(await response.json()) as ApiResponseExt<T>,
          headers
        }
      } else {
        return {
          error: { message: `Status: ${response.status}. ${response?.statusText}` },
          headers
        }
      }
    } catch (e) {
      return {
        error: { message: e?.message },
        headers: null
      };
    }
  };
}
