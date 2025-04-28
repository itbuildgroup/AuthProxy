export interface ErrorObject {
  code?: number;
  readonly message?: string | null;
}

export interface ApiResponse<T> {
  error?: ErrorObject | null;
  result?: T | null;
}

export interface ApiResponseExt<T> extends ApiResponse<T> {
  id?: number;
  headers?: Record<string, string> | null;
}

export interface AssertionResponse {
  authenticatorData?: string | null;
  clientDataJSON?: string | null;
  signature?: string | null;
  userHandle?: string | null;
}

export interface ResponseData {
  attestationObject?: string | null;
  clientDataJSON?: string | null;
  transports?: string[];
}

export interface AuthenticatorAttestationRawResponse {
  extensions?: AuthenticationExtensionsClientOutputs;
  id?: string | null;
  rawId?: string | null;
  response?: ResponseData;
  type?: PublicKeyCredentialType;
}

export interface AuthenticatorAssertionRawResponse {
  extensions?: AuthenticationExtensionsClientOutputs;
  id?: string | null;
  rawId?: string | null;
  response?: AssertionResponse;
  type?: PublicKeyCredentialType;
}

export interface LoginInfo {
  challenge_id?: string;
  code?: string | null;
  credential?: AuthenticatorAssertionRawResponse;
  credential_new?: AuthenticatorAttestationRawResponse;
  pass_key_flag?: boolean | null;
  public_key?: string | null;
  signature?: string | null;
}

export interface TelegramUserInfo {
  id?: number | null;
  first_name?: string | null;
  last_name?: string | null;
  username?: string | null;
  photo_url?: string | null;
  auth_date?: string | null;
  hash?: string | null;
}

export interface AuthOptions {
  challenge?: string | null;
  challenge_id?: string;
  fido2_options?: CredentialCreateOptions;
  rpId?: string | null;
  timeout?: number;
  userVerification?: UserVerificationRequirement | null;
  phone?: string | null;
}

export interface CredentialCreateOptions {
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: any;
  challenge?: string | null;
  errorMessage?: string | null;
  excludeCredentials?: PublicKeyCredentialDescriptor[] | null;
  extensions?: AuthenticationExtensionsClientInputs;
  pubKeyCredParams?: any[] | null;
  rp?: PublicKeyCredentialRpEntity;
  status?: string | null;
  timeout?: string;
  user?: any;
}

export interface UserLoginLog {
  device_info?: string | null;
  ip?: string | null;
  key_id?: string;
  key_sign_num?: number;
  login_type?: string | null;
  utc_time?: string;
}

export interface UserSessions {
  utc_create: string;
  id: number;
  user_agent: string;
  ip: string;
  login_type: string;
  current: boolean;
  flags: number;
  utc_last_access: string;
}

export interface AuthIn {
  challenge_id?: number;
  code?: string | null;
  credential?: AuthenticatorAssertionRawResponse;
  credential_new?: AuthenticatorAttestationRawResponse;
  pass_key_flag?: boolean | null;
  public_key?: string | null;
  signature?: string | null;
}

export interface ServerInfo {
  project_name: string;
  version: string;
  utc_time: Date;
}

export interface UserKey {
  current?: boolean;
  id?: number;
  key_type?: string | null;
  public_key?: string | null;
  utc_create?: string;
}
