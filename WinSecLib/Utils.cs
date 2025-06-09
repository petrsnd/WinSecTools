using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Windows.Win32;
using Windows.Win32.Security;

namespace Petrsnd.WinSecLib
{
    internal static class Utils
    {
        [SupportedOSPlatform("windows5.1.2600")]
        public static unsafe SecurityIdentifier? GetSid(PSID pSid)
        {
            if (!pSid.IsNull && PInvoke.IsValidSid(pSid))
            {
                var length = PInvoke.GetLengthSid(pSid);
                byte[] sidBytes = new byte[length];
                Marshal.Copy(new IntPtr(pSid), sidBytes, 0, (int)length);
                return new SecurityIdentifier(sidBytes, 0);
            }

            return null;
        }
    }
}
