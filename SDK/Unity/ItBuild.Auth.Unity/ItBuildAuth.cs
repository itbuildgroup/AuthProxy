using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace ItBuild.Auth.Unity
{
    /// <summary>
    /// ITBuild Auth Proxy methods
    /// </summary>
    public class ItBuildAuth
    {
        private HttpClient _client;
        public ItBuildAuth(HttpClient client)
        {
            _client = client;
        }

        /// <summary>
        /// Methods to authenticate project using user key (private key)
        /// </summary>
        /// <param name="privateKeyString">private key, registered and active key</param>
        /// <returns>the wrapped HTTP client, ready to use for authenticated calls</returns>
        public async Task<ResultWrapper<HttpClient>> AuthenticateWithUserKey(string privateKeyString)
        {
            try
            {
                ResultWrapper<LoginOptions>? options = null;
                // Getting the challenge
                options = await _client.GetFromJsonAsync<ResultWrapper<LoginOptions>>("auth/v1/login_options");
                if (options == null)
                    return ErrorObject.NetworkError;

                if (options.error != null)
                    return new ErrorObject(options.error.code, options.error.message);
                
                // Signing the challenge
                (var publicKeyBase64, var signatureBase64) = SignHelper.SignMessage(privateKeyString, options.result.challenge);
                
                // Sending the signed challenge
                LoginPayload loginPayload = new()
                {
                    signature = signatureBase64,
                    challenge_id = options.result.challenge_id,
                    public_key = publicKeyBase64
                };

                HttpResponseMessage loginResponseMessage =
                    await _client.PostAsJsonAsync<LoginPayload>("auth/v1/login", loginPayload);
                if (loginResponseMessage == null || loginResponseMessage.StatusCode != System.Net.HttpStatusCode.OK)
                    return ErrorObject.NetworkError;

                string responseContent = await loginResponseMessage.Content.ReadAsStringAsync();

                var resultObject = JsonSerializer.Deserialize<ResultWrapper<string>>(responseContent);

                if (resultObject == null)
                    return ErrorObject.ServerError;

                if (resultObject.error != null)
                    return new ErrorObject(resultObject.error.code, resultObject.error.message);

                if (resultObject.result == "Failure")
                    return ErrorObject.Failure;

                IEnumerable<string> cookies = loginResponseMessage
                    .Headers
                    .SingleOrDefault(header => header.Key == "Set-Cookie")
                    .Value;

                if (cookies == null || cookies.Count() == 0)
                    return ErrorObject.AuthenticationError;

                var parsedCookies = new System.Net.CookieContainer();
                parsedCookies.SetCookies(uri: _client.BaseAddress,
                                cookieHeader: cookies.FirstOrDefault());

                foreach (Cookie cookie in parsedCookies.GetAllCookies())
                {
                    if (cookie.Name != "sid") continue;

                    HttpClient authedClient = new HttpClient();
                    authedClient.BaseAddress = _client.BaseAddress;
                    foreach (var header in _client.DefaultRequestHeaders)
                        authedClient.DefaultRequestHeaders.Add(header.Key, header.Value);

                    authedClient.DefaultRequestHeaders.Add("Cookie", $"sid={cookie.Value}");

                    // Update the client for later use
                    _client = authedClient;
                    return authedClient;
                }
            }
            catch (Exception exception)
            {
                return new ErrorObject(-1, exception.Message);
            }
            return ErrorObject.Failure;
        }
        /// <summary>
        /// Gets the list of registered and active keys or returns 401 (Unauthorized)
        /// </summary>
        /// <returns>the wrapped list of user key data-objects</returns>
        public async Task<ResultWrapper<List<UserKeyData>>> GetUserKeys()
        {
            try
            {
                var userKeysResult = await _client.GetFromJsonAsync<ResultWrapper<List<UserKeyData>>>("auth/v1/user_keys");
                if (userKeysResult == null)
                    return ErrorObject.NetworkError;

                if (userKeysResult.error != null)
                    return new ErrorObject(userKeysResult.error.code, userKeysResult.error.message);

                return userKeysResult;
            }
            catch (Exception exception)
            {
                if (exception is HttpRequestException hhtpEx && hhtpEx.StatusCode == HttpStatusCode.Unauthorized)
                    return ErrorObject.Unauthorized;

                return new ErrorObject(-1, exception.Message);
            }
        }
        /// <summary>
        /// Gets login log for sender
        /// </summary>
        /// <returns>the wrapped list of loging log data-objects</returns>
        public async Task<ResultWrapper<List<LoginLogData>>> GetLoginLog()
        {
            try
            {
                var loginLogResult = await _client.GetFromJsonAsync<ResultWrapper<List<LoginLogData>>>("auth/v1/login_log");
                if (loginLogResult == null)
                    return ErrorObject.NetworkError;

                if (loginLogResult.error != null)
                    return new ErrorObject(loginLogResult.error.code, loginLogResult.error.message);

                return loginLogResult;
            }
            catch (Exception exception)
            {
                if (exception is HttpRequestException httpReqException && httpReqException.StatusCode == HttpStatusCode.Unauthorized)
                    return ErrorObject.Unauthorized;

                return new ErrorObject(-1, exception.Message);
            }
        }
        /// <summary>
        /// Retrieves user's sessions
        /// </summary>
        /// <returns>the wrapped list of session data-objects</returns>
        public async Task<ResultWrapper<List<SessionData>>> GetSessions()
        {
            try
            {
                var sessionsResult = await _client.GetFromJsonAsync<ResultWrapper<List<SessionData>>>("auth/v1/sessions");
                if (sessionsResult == null)
                    return ErrorObject.NetworkError;

                if (sessionsResult.error != null)
                    return new ErrorObject(sessionsResult.error.code, sessionsResult.error.message);

                return sessionsResult;
            }
            catch (Exception exception)
            {
                if (exception is HttpRequestException httpReqException && httpReqException.StatusCode == HttpStatusCode.Unauthorized)
                    return ErrorObject.Unauthorized;

                return new ErrorObject(-1, exception.Message);
            }
        }
        /// <summary>
        /// Attempts to close all sessions but current or a session with a given ID
        /// </summary>
        /// <param name="sessionInternalId">if not null closes the session with given internal ID</param>
        /// <returns>wrapped string: 'Success' or 'Failure'</returns>
        public async Task<ResultWrapper<string>> CloseSessions(long? sessionInternalId = null)
        {
            try
            {
                var closeSessionsResult = await _client.GetFromJsonAsync<ResultWrapper<string>>(
                    $"auth/v1/close_sessions{(sessionInternalId == null ? "" : $"?id={sessionInternalId}")}");
                if (closeSessionsResult == null)
                    return ErrorObject.NetworkError;

                if (closeSessionsResult.error != null)
                    return new ErrorObject(closeSessionsResult.error.code, closeSessionsResult.error.message);

                return closeSessionsResult;
            }
            catch (Exception exception)
            {
                if (exception is HttpRequestException httpReqException && httpReqException.StatusCode == HttpStatusCode.Unauthorized)
                    return ErrorObject.Unauthorized;

                return new ErrorObject(-1, exception.Message);
            }
        }
    }
    public class LoginOptions
    {
        public long challenge_id { get; set; }
        public string challenge { get; set; }
        public string rpId { get; set; }
        public long timeout { get; set; }
        public string userVerification { get; set; }
        public object fido2_options { get; set; }
        public string? phone { get; set; }
    }
    public class LoginPayload
    {
        public long challenge_id { get; set; }
        public object credential { get; set; }
        public string public_key { get; set; }
        public string signature { get; set; }
    }
    /// <summary>
    /// User key data-object
    /// </summary>
    public class UserKeyData
    {
        /// <summary>
        /// The date and time when the key was created (UTC)
        /// </summary>
        public DateTimeOffset utc_create { get; set; }
        /// <summary>
        /// Key internal ID
        /// </summary>
        public long id { get; set; }
        /// <summary>
        /// Key's public key
        /// </summary>
        public string public_key { get; set; }
        /// <summary>
        /// Key type
        /// </summary>
        public string key_type { get; set; }
        /// <summary>
        /// The current key is marked with 'true'
        /// </summary>
        public bool current { get; set; }
    }
    /// <summary>
    /// Login log data-object
    /// </summary>
    public class LoginLogData
    {
        /// <summary>
        /// Login time (UTC)
        /// </summary>
        public DateTimeOffset utc_time { get; set; }
        /// <summary>
        /// Key identificator
        /// </summary>
        public long key_id { get; set; }
        /// <summary>
        /// Key usage number
        /// </summary>
        public long key_sign_num { get; set; }
        /// <summary>
        /// IP address of login (if available)
        /// </summary>
        public string ip { get; set; }
        /// <summary>
        /// Information about the device
        /// </summary>
        public string device_info { get; set; }
        /// <summary>
        /// Login type
        /// </summary>
        public string login_type { get; set; }
    }
    /// <summary>
    /// Session data
    /// </summary>
    public partial class SessionData
    {
        /// <summary>
        /// Date and time of session creation (UTC)
        /// </summary>
        public DateTimeOffset utc_create { get; set; }
        /// <summary>
        /// Internal session ID
        /// </summary>
        public long id { get; set; }
        /// <summary>
        /// User-Agent for the session
        /// </summary>
        public string user_agent { get; set; }
        /// <summary>
        /// IP address of the session (if available)
        /// </summary>
        public string ip { get; set; }
        /// <summary>
        /// Session's login type
        /// </summary>
        public string login_type { get; set; }
        /// <summary>
        /// The current session is marked with 'true'
        /// </summary>
        public bool current { get; set; }
        /// <summary>
        /// Session flags
        /// </summary>
        public long flags { get; set; }
        /// <summary>
        /// Session's last access time
        /// </summary>
        public DateTimeOffset utc_last_access { get; set; }
    }
}
