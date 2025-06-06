using System.Security;

namespace Petrsnd.NetApiTool
{
    internal static class Extensions
    {
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
