using System;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Authentication.Identity;

namespace Petrsnd.WinSecLib
{
    // When I started in to work on the LSA code, because it used LSA_UNICODE_STRINGs, the generated friendly
    // overloads need a little extra help.  So, I wrote the on top of their friendly methods, because they
    // provide safehandles and other useful bits.

    [SupportedOSPlatform("windows5.1.2600")]
    internal static class LsaApiPInvokeHelper
    {
        public static unsafe LsaCloseSafeHandle CallLsaOpenPolicy(string? systemName, uint desiredAccess)
        {
            if (systemName?.Length > ushort.MaxValue)
            {
                throw new ArgumentException("System name exceeds the max length of an LSA unicode string", nameof(systemName));
            }

            fixed (char* systemNameLocal = systemName)
            {
                LSA_UNICODE_STRING? systemNameLsaString = null;
                if (systemName != null)
                {
                    systemNameLsaString = new LSA_UNICODE_STRING
                    {
                        Length = (ushort)systemName.Length,
                        MaximumLength = (ushort)systemName.Length,
                        Buffer = systemNameLocal
                    };
                }

                // This is passed in but doesn't get used -- the docs say to initialize it to all zeros
                var objectAttributes = new LSA_OBJECT_ATTRIBUTES
                {
                    Length = 0,
                    RootDirectory = HANDLE.Null,
                    ObjectName = null,
                    Attributes = 0,
                    SecurityDescriptor = null,
                    SecurityQualityOfService = null,
                };

                LsaCloseSafeHandle policyHandle;
                var rval = PInvoke.LsaOpenPolicy(systemNameLsaString, in objectAttributes, desiredAccess, out policyHandle);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                return policyHandle;
            }
        }

        public static unsafe string CallLsaRetrievePrivateData(LsaCloseSafeHandle policyHandle, string keyName)
        {
            fixed (char* keyNameLocal = keyName)
            {
                var keyNameLsaString = new LSA_UNICODE_STRING
                {
                    Length = (ushort)keyName.Length,
                    MaximumLength = (ushort)keyName.Length,
                    Buffer = keyNameLocal
                };

                LSA_UNICODE_STRING* privateDataLsaString;
                var rval = PInvoke.LsaRetrievePrivateData(policyHandle, keyNameLsaString, out privateDataLsaString);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                var privateData = new string(privateDataLsaString->Buffer, 0, privateDataLsaString->Length);
                rval = PInvoke.LsaFreeMemory(privateDataLsaString);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                return privateData;
            }
        }

        public static unsafe void CallLsaStorePrivateData(LsaCloseSafeHandle policyHandle, string keyName, string privateData)
        {
            fixed (char* keyNameLocal = keyName)
            {
                fixed (char* privateDataLocal = privateData)
                {
                    var keyNameLsaString = new LSA_UNICODE_STRING
                    {
                        Length = (ushort)keyName.Length,
                        MaximumLength = (ushort)keyName.Length,
                        Buffer = keyNameLocal
                    };

                    var privateDataLsaString = new LSA_UNICODE_STRING
                    {
                        Length = (ushort)privateData.Length,
                        MaximumLength = (ushort)privateData.Length,
                        Buffer = privateDataLocal
                    };

                    var rval = PInvoke.LsaStorePrivateData(policyHandle, keyNameLsaString, privateDataLsaString);
                    if (rval != NTSTATUS.STATUS_SUCCESS)
                    {
                        throw new LsaApiException(rval);
                    }
                }
            }
        }
    }
}
