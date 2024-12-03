using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities.Encoders;

namespace ItBuild.Auth.Unity;

public class SignHelper
{
    /// <summary>
    /// Signs the message with Ed25519Signer kreated from hex ecoded private key string
    /// </summary>
    /// <param name="privateKeyString"></param>
    /// <param name="messageBase64"></param>
    /// <returns></returns>
    public static (string publicKeyBase64, string signatureBase64) SignMessage(string privateKeyString, string messageBase64)
    {
        byte[] challengeBytes = Convert.FromBase64String(messageBase64.Replace("-", "+").Replace("_", "/"));

        Ed25519Signer signer = new Ed25519Signer();
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(
            Hex.DecodeStrict(privateKeyString));

        signer.Init(true, privateKey);
        signer.BlockUpdate(challengeBytes, 0, challengeBytes.Length);
        byte[] signedChallenge = signer.GenerateSignature();

        // Encode public key and signature to Base64 URL format
        string publicKeyBase64 = CoerceToBase64Url(privateKey.GeneratePublicKey().GetEncoded());
        string signatureBase64 = CoerceToBase64Url(signedChallenge);

        return (publicKeyBase64, signatureBase64);
    }
    private static string CoerceToBase64Url(byte[] bytes)
    {
        string base64 = Convert.ToBase64String(bytes);
        return base64.Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}