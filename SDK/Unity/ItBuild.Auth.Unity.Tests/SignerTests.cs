namespace ItBuild.Auth.Unity.Tests
{
    public class SignerTests
    { 
        [Test]
        public async Task SignMessageCreatesCorrectSignature()
        {
            var privateKeyString = "a32be8142c2680590828a64ad46c64bbbe50609de1f23d52cdd69187ad9d62ba";
            var message = "Wr2GEXAnBhvb59-QodZ-vnpD-bOYHkSq";

            var correctPublicKey = "AgsHp5s4xWAPbL5sXrLixCNI5k7TgdxPhJtQnwyHvqY";
            var correctSignature = "xRN5OvTl21QazSWGUX-abKEl6RWWC0e6aCscdVUgrPEw21gpw33UhiX4DtomJzYuyIAIaMjt2g8eaumV4AxgCw";

            // Signing the message
            (var publicKeyBase64, var signatureBase64) = SignHelper.SignMessage(privateKeyString, message);

            Assert.That(publicKeyBase64, Is.EqualTo(correctPublicKey));
            Assert.That(signatureBase64, Is.EqualTo(correctSignature));
        }
    }
}