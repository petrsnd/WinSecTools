using System;

namespace Petrsnd.WinSecLib
{
    public class NetApiException : Exception
    {
        internal NetApiException(Constants.NET_API_STATUS status) :
            base($"ERROR: {status}")
        {
            Status = status;
        }

        internal Constants.NET_API_STATUS Status { private set; get; }
    }
}
