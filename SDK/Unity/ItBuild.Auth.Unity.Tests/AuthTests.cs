namespace ItBuild.Auth.Unity.Tests
{
    public class AuthCodeExamples
    { 
        public async Task AuthenticateWithUserKeyAuthenticates()
        {
            // Setting up the client to authenticate

            // The base URL of API (contact support, if you don't have one)
            string baseApiUrl = "BASE_URL";

            // Private key (it's better to use 'user key' type for backend authentication)
            // (contact support if you don't have one)
            string privateKeyString = "PRIVATE_KEY_STRING";

            // Device unique device ID, you can use any random string or contact support
            string projectDeviceUid = Guid.NewGuid().ToString();
            var unauthedClient = ApiHttpClientHelper.SetupUnauthClient(baseApiUrl, projectDeviceUid);

            // Authenticate
            ItBuildAuth auth = new(unauthedClient);
            var authResult = await auth.AuthenticateWithUserKey(privateKeyString);
            
            if (authResult.error != null)
            {
                // The authentication call was unsuccesful, 
                // the error object contains more information,
                // including potential exception's details
                return;
            }

            // After successful authentication the method 
            // returns HttpClient object that can be used 
            // to make authenticated calls.
            // The internal client within ItBuildAuth object 
            // also becomes authenticated.
            HttpClient authedHttpClient = authResult.result;
            
            // This call should return the list of keys 
            // for currently logged in user
            var userKeysResult = await auth.GetUserKeys();

            if (userKeysResult.error == ErrorObject.Unauthorized)
            {
                // The session's expired (it will expire after 24 hours of inactivity) or closed.
                // IMPORTANT: the proxy doesn't preserve sessions during service restart (planned or unplanned)
                authResult = await auth.AuthenticateWithUserKey(privateKeyString);
            }

            // Get the sessions
            var sessionsResult = await auth.GetSessions();
            if (sessionsResult.error == ErrorObject.Unauthorized)
            {
                // The session's expired (it will expire after 24 hours of inactivity) or closed.
                authResult = await auth.AuthenticateWithUserKey(privateKeyString);
            }

            if (sessionsResult.result == null)
                return;

            // Closing the session
            var currentSession = sessionsResult.result.FirstOrDefault(x => x.current);

            if (currentSession == null)
                return;
            
            var closeSessionResult = await auth.CloseSessions(currentSession.id);
            if (closeSessionResult.error != null || closeSessionResult.result == "Failure")
                return;
            
            // Session was succesfully closed
        }
    }
}