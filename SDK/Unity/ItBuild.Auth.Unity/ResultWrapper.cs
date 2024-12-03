using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ItBuild.Auth.Unity
{
    /// <summary>
    /// Result wrapper for API calls and SDK methods
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ResultWrapper<T>
    {
        public ResultWrapper() { }

        public ResultWrapper(T result, int id = 0)
        {
            this.result = result;
            this.id = id;
        }
        public ResultWrapper(ErrorObject error, int id = 0)
        {
            this.error = error;
            this.id = id;
        }
        /// <summary>
        /// Is the result "Success"
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public bool IsSuccess => result is string str && string.Equals(str, "Success", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Response-object: null, if error
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public T? result { get; set; }
        /// <summary>
        /// Error-object
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        public ErrorObject? error { get; set; }
        /// <summary>
        /// Request id, if necessary
        /// </summary>
        public int id { get; set; }

        public static implicit operator ResultWrapper<T>(T obj) => new(obj);
        public static implicit operator ResultWrapper<T>(ErrorObject obj) => new(obj);
    }
}
