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

export class AuthProxyClient {
  public readonly BaseUrl: string = null;

  private esLink: EventSource = null;
  private isConnectedES: boolean = false;
  private sessionId: string | null = null;
  private deviceGuid: string | null = null;

  constructor(baseUrl: string) {
    this.BaseUrl = baseUrl;
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
          resolution: `${1}x${1}`,
          device_guid: this.getDeviceGuid()
        }
      }
    );

    if (loginResponse.result && loginResponse.result !== "Failure") {
      let sid = loginResponse.headers['set-cookie'].match(/sid=([^;]+)/)[1];
      this.sessionId = sid;
    }

    return loginResponse;
  };

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
          resolution: `${1}x${1}`,
          device_guid: this.getDeviceGuid()
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
  public Subscribe(handleMessage: (object: unknown) => void = () => {}): boolean {
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

      this.esLink.onmessage = (event: MessageEvent<{ data: unknown }>) => {
        var message = this.getMessageFromEvent(event.data);
        handleMessage(message);
      };

      this.esLink.onerror = (error: unknown) => {
        console.error("EventSource error:", error);
      };
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
    if (!this.deviceGuid) {
      this.deviceGuid = crypto.randomUUID();
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
      const response = await fetch(this.BaseUrl + url, {
        credentials: "include",
        ...init,
        headers: {
          ...defaultHeaders,
          ...init.headers,
          ...(this.sessionId ? { Cookie: `sid=${this.sessionId}` } : {})
        }
      });

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
