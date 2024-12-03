using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ItBuild.Auth.Unity
{
    /// <summary>
    /// Error-object for response wrapper
    /// </summary>
    /// <param name="code">error code</param>
    /// <param name="message">error message</param>
    public record ErrorObject(int code, string message)
    {
        public override string ToString() => $"Error {code}: {message}";

        public static ErrorObject ServerError => new(-31001, "Server error. Something went wrong :(");
        public static ErrorObject Failure => new(-31002, "Failure. Not successful");
        public static ErrorObject AuthenticationError => new(-31003, "Server authentication error");
        public static ErrorObject NetworkError => new(-31004, "Network error");
        public static ErrorObject Unauthorized => new(-31005, "Unauthorized call to API");

        public static implicit operator int(ErrorObject obj) => obj.code;
    }
}
