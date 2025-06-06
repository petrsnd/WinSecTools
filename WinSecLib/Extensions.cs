using System.Collections.Generic;
using System.Net;
using System.Runtime.Versioning;
using System.Security;

namespace Petrsnd.WinSecLib
{
    static internal class InternalExtensions
    {
        public static string ToInsecureString(this SecureString thisSecureString)
        {
            return new NetworkCredential(string.Empty, thisSecureString).Password;
        }
    }

    static public class PublicExtensions
    {
        [SupportedOSPlatform("windows5.0")]
        public static string? AsJson(this UserInformation userInformation)
        {
            if (userInformation == null)
            {
                return null;
            }

            return NetApi.JsonSerialize(userInformation);
        }

        [SupportedOSPlatform("windows5.0")]
        public static string? AsJson(this IEnumerable<UserInformation> userInformations)
        {
            if (userInformations == null)
            {
                return null;
            }

            return NetApi.JsonSerialize(userInformations);
        }
    }
}
