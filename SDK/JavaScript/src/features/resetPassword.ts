
import { ResetPassword } from "../api";
import formatAsNumber from "../utils/formatAsNumber";

/**
 * Call password reset
 * @param phone User's phone number
 * @returns status string on success
 * @returns `null` on error
 */
export async function resetPassword(phone: string): Promise<string | null> {
  if (!formatAsNumber(phone.trim())) return null;

  const response = await ResetPassword(phone);

  if (response.result || response.result !== "Failure") {
    return response.result;
  };

  return null;
};
