
import { AuthOptions } from "@/api/model";
import { apiRegisterOptions } from "../api";

interface INewKeyParams {
  code?: string;
  sid?: string;
}

/**
 * Initialize new key registration
 * @param code Code from email (unauthorized)
 * @param sid User's session id (authorized)
 * @returns object of {@link AuthOptions} on success
 * @returns `null` on error
 */
export async function initializeNewKey({code, sid}: INewKeyParams): Promise<AuthOptions | null> {
  if (!code.trim()) return null;

  const response = await apiRegisterOptions(code, sid);

  if (response.result) {
    return response.result;
  };

  return null;
};
