using System;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.System.Diagnostics.Debug;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows5.1.2600")]
    public class Win32ErrorException : Exception
    {
        public Win32ErrorException(int win32Error) :
            base(FormatMessage(win32Error))
        { }

        private static unsafe string FormatMessage(int win32Error)
        {
            var buffer = new char[32768]; // 32KiB
            var bytesWritten = PInvoke.FormatMessage(FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_FROM_SYSTEM,
                null, (uint)win32Error, 0U, buffer.AsSpan(), (uint)buffer.Length, (sbyte**)IntPtr.Zero.ToPointer());
            if (bytesWritten == 0)
            {
                return $"Error {win32Error}: No message found or FormatMessage failed.";
            }

            fixed (char* bufferLocal = buffer)
            {
                return $"Error {win32Error}: {new string(bufferLocal, 0, (int)bytesWritten)}";
            }
        }
    }
}
