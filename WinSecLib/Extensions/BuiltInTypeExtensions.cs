using System.Collections.Generic;
using System.Net;
using System.Runtime.Versioning;
using System.Security;

namespace Petrsnd.WinSecLib.Extensions
{
    static public class BuiltInTypeExtensions
    {
        public static string ToInsecureString(this SecureString thisSecureString)
        {
            return new NetworkCredential(string.Empty, thisSecureString).Password;
        }

        public static SecureString? ToSecureString(this string thisString)
        {
            if (string.IsNullOrWhiteSpace(thisString))
            {
                return null;
            }

            var result = new SecureString();
            foreach (var c in thisString)
            {
                result.AppendChar(c);
            }

            return result;
        }
    }
}
