using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.System.SystemInformation;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows5.1.2600")]
    internal static class SysInfoApi
    {
        public static string GetComputerNetBiosName()
        {
            return GetComputerNameInternal(COMPUTER_NAME_FORMAT.ComputerNameNetBIOS);
        }

        public static string GetComputerDnsHostname()
        {
            return GetComputerNameInternal(COMPUTER_NAME_FORMAT.ComputerNameDnsHostname);
        }

        public static string GetComputerDnsDomain()
        {
            return GetComputerNameInternal(COMPUTER_NAME_FORMAT.ComputerNameDnsDomain);
        }

        public static string GetComputerDnsFullyQualified()
        {
            return GetComputerNameInternal(COMPUTER_NAME_FORMAT.ComputerNameDnsFullyQualified);
        }

        private static string GetComputerNameInternal(COMPUTER_NAME_FORMAT computerNameFormat)
        {
            var bufferSize = 8192U;  // 8KiB
            var buffer = new char[bufferSize];
            if (PInvoke.GetComputerNameEx(computerNameFormat, buffer.AsSpan(), ref bufferSize) != 0)
            {
                throw new Win32ErrorException(Marshal.GetLastWin32Error());
            }
            return new string(buffer, 0, (int)bufferSize);
        }
    }
}
