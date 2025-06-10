using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.NetManagement;

namespace Petrsnd.WinSecLib
{
    // I didn't use the friendly overloads from CsWin32 because they generated weird code for NetUserSetInfo with
    // an `in byte` buf parameter for the opaque `byte*` buffer that depends on the level parameter. It was easier to
    // just craft the convenience method myself. So, I just turned off friendly generation altogether.

    internal static class NetApiPInvokeHelper
    {
        internal static uint GetNetApiLevelForType<T>(T? userInfo)
        {
            return userInfo switch
            {
                USER_INFO_0 => 0,
                USER_INFO_1 => 1,
                USER_INFO_2 => 2,
                USER_INFO_3 => 3,
                USER_INFO_4 => 4,
                USER_INFO_10 => 10,
                USER_INFO_11 => 11,
                USER_INFO_20 => 20,
                USER_INFO_21 => 21,
                USER_INFO_23 => 23,
                USER_INFO_24 => 24,
                USER_INFO_1003 => 1003,
                _ => 0,
            };
        }

        internal static NetApiUserInformation ConvertToUserInformation<T>(T userInfo)
        {
            var method = typeof(NetApiUserInformation).GetMethod("CreateFrom", BindingFlags.NonPublic | BindingFlags.Static, new Type[] { typeof(T) });
            if (method == null)
            {
                throw new InvalidOperationException($"Unable to find UserInformation.CreateFrom method for parameter type: {typeof(T)}");
            }

            var convertedObject = method.Invoke(null, new object[] { userInfo! });
            if (convertedObject == null)
            {
                throw new InvalidOperationException($"UserInformation.CreateFrom invocation returned null for parameter type: {typeof(T)}");
            }

            return (NetApiUserInformation)convertedObject;
        }

        [SupportedOSPlatform("windows5.0")]
        internal static unsafe NetApiUserInformation[] CallNetUserEnum<T>(string? servername, NET_USER_ENUM_FILTER_FLAGS filter = 0)
        {
            fixed (char* servernameLocal = servername)
            {
                var userInfoList = new List<NetApiUserInformation>();
                uint resume_handle = 0;
                bool done = false;
                while (!done)
                {
                    // already fixed due to unsafe context
                    IntPtr bufptr = IntPtr.Zero;
                    uint entriesread = 0;
                    uint totalentries = 0;

                    uint rval = PInvoke.NetUserEnum(servernameLocal, GetNetApiLevelForType<T>(default), filter, (byte**)&bufptr, Constants.MAX_PREFERRED_LENGTH, &entriesread, &totalentries, &resume_handle);
                    try
                    {
                        if ((Constants.NET_API_STATUS)rval == Constants.NET_API_STATUS.NERR_Success ||
                        (Constants.NET_API_STATUS)rval == Constants.NET_API_STATUS.ERROR_MORE_DATA)
                        {
                            var span = new Span<T>(bufptr.ToPointer(), (int)entriesread);
                            foreach (var userInfo in span)
                            {
                                userInfoList.Add(ConvertToUserInformation(userInfo));
                            }

                            done = ((Constants.NET_API_STATUS)rval == Constants.NET_API_STATUS.NERR_Success);
                        }
                        else
                        {
                            throw new NetApiException((Constants.NET_API_STATUS)rval);
                        }
                    }
                    finally
                    {
                        rval = PInvoke.NetApiBufferFree((void*)bufptr);
                        if ((Constants.NET_API_STATUS)rval != Constants.NET_API_STATUS.NERR_Success)
                        {
                            throw new NetApiException((Constants.NET_API_STATUS)rval);
                        }
                    }
                }

                return userInfoList.ToArray();
            }
        }


        [SupportedOSPlatform("windows5.1.2600")]
        internal static unsafe NetApiUserInformation CallNetUserGetInfo<T>(string? servername, string? username)
        {
            fixed (char* servernameLocal = servername)
            {
                fixed (char* usernameLocal = username)
                {
                    IntPtr bufptr = IntPtr.Zero;
                    uint rval = PInvoke.NetUserGetInfo(servernameLocal, usernameLocal, GetNetApiLevelForType<T>(default), (byte**)&bufptr);
                    try
                    {
                        var userInfo = default(T);
                        if ((Constants.NET_API_STATUS)rval != Constants.NET_API_STATUS.NERR_Success)
                        {
                            throw new NetApiException((Constants.NET_API_STATUS)rval);
                        }

                        if (bufptr == IntPtr.Zero)
                        {
                            throw new Exception("NetApi method call returned success, but out pointer was null");
                        }

                        userInfo = (T)Marshal.PtrToStructure(bufptr, typeof(T))!;
                        return ConvertToUserInformation(userInfo);
                    }
                    finally
                    {
                        rval = PInvoke.NetApiBufferFree((void*)bufptr);
                        if ((Constants.NET_API_STATUS)rval != Constants.NET_API_STATUS.NERR_Success)
                        {
                            throw new NetApiException((Constants.NET_API_STATUS)rval);
                        }
                    }
                }
            }
        }

        [SupportedOSPlatform("windows5.0")]
        internal static unsafe void CallNetUserSetInfo(string? servername, string? username, string? password)
        {
            fixed (char* servernameLocal = servername)
            {
                fixed (char* usernameLocal = username)
                {
                    fixed (char* passwordlocal = password)
                    {
                        var userInfo = new USER_INFO_1003
                        {
                            usri1003_password = new PWSTR(passwordlocal),
                        };

                        uint rval = PInvoke.NetUserSetInfo(servernameLocal, usernameLocal, 1003U, (byte*)&userInfo, null);
                        if ((Constants.NET_API_STATUS)rval != Constants.NET_API_STATUS.NERR_Success)
                        {
                            throw new NetApiException((Constants.NET_API_STATUS)rval);
                        }
                    }
                }
            }
        }
    }
}
