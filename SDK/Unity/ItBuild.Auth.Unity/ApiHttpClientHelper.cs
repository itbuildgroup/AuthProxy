namespace ItBuild.Auth.Unity
{
    /// <summary>
    /// Helper to setup the HttpClient for making unauthorised calls to API
    /// </summary>
    public class ApiHttpClientHelper
    {
        /// <summary>
        /// Static method that creates HttpClient for making unauthorised calls to API
        /// </summary>
        /// <param name="apiBasUrl">base address for API calls</param>
        /// <param name="projectDeviceUid">GUID that identifies the device</param>
        /// <returns></returns>
        public static HttpClient SetupUnauthClient(string apiBasUrl, string projectDeviceUid)
        {
            var client = new HttpClient();
            client.BaseAddress = new Uri(apiBasUrl);
            client.DefaultRequestHeaders.Add("device_guid", projectDeviceUid);

            return client;
        }
    }
}