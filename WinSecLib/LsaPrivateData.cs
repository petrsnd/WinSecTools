using System;
using System.Runtime.CompilerServices;
using System.Text;
using Windows.Win32.Security.Authentication.Identity;

namespace Petrsnd.WinSecLib
{
    public class LsaPrivateData
    {
        public LsaPrivateData(string str)
        {
            Buffer = str.ToCharArray();
        }

        public LsaPrivateData(byte[] buf)
        {
            Buffer = new char[buf.Length];
            Array.Copy(buf, Buffer, buf.Length);
        }

        internal unsafe LsaPrivateData(LSA_UNICODE_STRING lsaUnicodeStr)
        {
            Buffer = new char[lsaUnicodeStr.Length / sizeof(char)];
            fixed (char* bufPtr = Buffer)
            {
                var bufSpan = new Span<char>(bufPtr, Buffer.Length);
                lsaUnicodeStr.Buffer.AsSpan().CopyTo(bufSpan);
            }
        }

        public char[] Buffer { get; set; }

        public int Length => Buffer.Length;

        public int LengthInBytes => Length * sizeof(char);

        public override string ToString()
        {
            return new string(Buffer);
        }

        public string ToHexString()
        {
            return BitConverter.ToString(Encoding.Unicode.GetBytes(Buffer)).Replace('-', ' ');
        }
    }
}
