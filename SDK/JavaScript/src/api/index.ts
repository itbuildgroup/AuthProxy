import ApiRequest from "./api-request";
import { AuthIn, AuthOptions, LoginInfo, TelegramUserInfo, UserLoginLog, UserSessions, ServerInfo, UserKey } from "./model";

export const apiGetInfo = () =>
  ApiRequest<ServerInfo>("auth/v1/get_info", {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json"
    }
  });

export const apiLoginLog = () =>
  ApiRequest<UserLoginLog[]>("auth/v1/login_log", {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json"
    }
  });

export const apiTelegramLogin = (data: TelegramUserInfo) => {
  const queryParams = new URLSearchParams();
  Object.entries(data).forEach(([key, value]) => {
    if (value) {
      queryParams.set(key, value);
    }
  });

  return ApiRequest<string>(`auth/v1/telegram?${queryParams.toString()}`, {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      device_guid: null
    }
  });
};

export const apiLoginOptions = () =>
  ApiRequest<AuthOptions>(
    "auth/v1/login_options",
    {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json"
      }
    }
  );

export const apiLogin = (data: LoginInfo) =>
  ApiRequest<string>(
    "auth/v1/login",
    {
      method: "POST",
      credentials: "include",
      body: JSON.stringify(data),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        device_guid: null
      }
    }
  );

export const ResetPassword = (phone: string) =>
  ApiRequest<string>(
    `auth/v1/reset_password?phone=${phone}`,
    {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json"
      }
    }
  );

export const apiRegisterOptions = (emailCode?: string | null) =>
  ApiRequest<AuthOptions>(
    `auth/v1/register_options${emailCode ? `?code=${emailCode}` : ""}`,
    {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json"
      }
    }
  );

export const RegisterKey = (data: AuthIn) =>
  ApiRequest<string>(
    "auth/v1/register_key",
    {
      method: "POST",
      credentials: "include",
      body: JSON.stringify(data),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      }
    }
  );

export const apiGetLoginLogs = () =>
  ApiRequest<UserLoginLog[]>("auth/v1/login_log", {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });

export const apiGetSessions = (current?: boolean) => {
  const queryParams = new URLSearchParams();
  if (current) queryParams.set("current", `${current}`);

  return ApiRequest<UserSessions[]>(`auth/v1/sessions?${queryParams.toString()}`, {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });
};

export const apiCloseSessions = (id?: number) => {
  const queryParams = new URLSearchParams();
  if (id) queryParams.set("id", `${id}`);

  return ApiRequest<string | null>(`auth/v1/close_sessions?${queryParams.toString()}`, {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });
};

export const apiUserKeys = () =>
  ApiRequest<UserKey[]>(`auth/v1/user_keys`, {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });

export const apiLogout = () =>
  ApiRequest<string>(`auth/v1/logout`, {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });

export const apiRemoveKey = (key_id: number) => {
  const queryParams = new URLSearchParams();
  if (key_id) queryParams.set("key_id", `${key_id}`);

  return ApiRequest<string | null>(`auth/v1/remove_key?${queryParams.toString()}`, {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });
};
