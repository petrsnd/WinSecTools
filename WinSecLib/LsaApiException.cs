using System;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Diagnostics.Debug;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows5.1.2600")]
    public class LsaApiException : Exception
    {
        internal LsaApiException(NTSTATUS status) :
            base(FormatMessage(status))
        {
            Status = status;
            WinError = PInvoke.LsaNtStatusToWinError(status);
        }

        internal NTSTATUS Status { private set; get; }

        internal uint WinError { private set; get; }

        private static unsafe string FormatMessage(NTSTATUS status)
        {
            var winError = PInvoke.LsaNtStatusToWinError(status);
            var buffer = new char[32768]; // 32KiB
            var bytesWritten = PInvoke.FormatMessage(FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_FROM_SYSTEM,
                null, winError, 0U, buffer.AsSpan(), (uint)buffer.Length, (sbyte**)IntPtr.Zero.ToPointer());
            if (bytesWritten == 0)
            {
                return $"NTSTATUS {status:X} ({winError}): No message found or FormatMessage failed.";
            }

            fixed (char* bufferLocal = buffer)
            {
                return $"NTSTATUS {status:X} ({winError}): {new string(bufferLocal, 0, (int)bytesWritten)}";
            }
        }
    }
}
