using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
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
        public static unsafe string? ConvertLsaUnicodeStringToString(LSA_UNICODE_STRING lsaUnicodeStr)
        {
            if (lsaUnicodeStr.Buffer == null)
            {
                return null;
            }

            return new string(lsaUnicodeStr.Buffer, 0, lsaUnicodeStr.Length / sizeof(char));
        }

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
                        Length = (ushort)(systemName.Length * sizeof(char)),
                        MaximumLength = (ushort)(systemName.Length * sizeof(char)),
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

        public static unsafe LsaPrivateData CallLsaRetrievePrivateData(LsaCloseSafeHandle policyHandle, string keyName)
        {
            fixed (char* keyNameLocal = keyName)
            {
                var keyNameLsaString = new LSA_UNICODE_STRING
                {
                    Length = (ushort)(keyName.Length * sizeof(char)),
                    MaximumLength = (ushort)(keyName.Length * sizeof(char)),
                    Buffer = keyNameLocal
                };

                LSA_UNICODE_STRING* privateDataLsaString;
                var rval = PInvoke.LsaRetrievePrivateData(policyHandle, keyNameLsaString, out privateDataLsaString);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                var privateData = new LsaPrivateData(*privateDataLsaString);
                rval = PInvoke.LsaFreeMemory(privateDataLsaString);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                return privateData;
            }
        }

        public static unsafe void CallLsaStorePrivateData(LsaCloseSafeHandle policyHandle, string keyName, LsaPrivateData privateData)
        {
            fixed (char* keyNameLocal = keyName)
            {
                fixed (char* privateDataLocal = privateData.Buffer)
                {
                    var keyNameLsaString = new LSA_UNICODE_STRING
                    {
                        Length = (ushort)(keyName.Length * sizeof(char)),
                        MaximumLength = (ushort)(keyName.Length * sizeof(char)),
                        Buffer = keyNameLocal
                    };

                    var privateDataLsaString = new LSA_UNICODE_STRING
                    {
                        Length = (ushort)(privateData.Length * sizeof(char)),
                        MaximumLength = (ushort)(privateData.Length * sizeof(char)),
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

        public static unsafe LsaDomainDnsInfo CallLsaQueryInformationPolicy(LsaCloseSafeHandle policyHandle)
        {
            // Only supporting PolicyDnsDomainInformation, because pretty much everything else is deprecated
            var rval = PInvoke.LsaQueryInformationPolicy(policyHandle, POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation, out void* buffer);
            if (rval != NTSTATUS.STATUS_SUCCESS)
            {
                throw new LsaApiException(rval);
            }

            try
            {
                IntPtr bufptr = new IntPtr(buffer);
                var userInfo = (POLICY_DNS_DOMAIN_INFO)Marshal.PtrToStructure(bufptr, typeof(POLICY_DNS_DOMAIN_INFO))!;
                return new LsaDomainDnsInfo(userInfo);
            }
            finally
            {
                PInvoke.LsaFreeMemory(buffer);
            }
        }

        public static unsafe LsaTrustedDomain[] CallLsaEnumerateTrustedDomainsEx(LsaCloseSafeHandle policyHandle)
        {
            var trustedDomainList = new List<LsaTrustedDomain>();
            uint enumerationHandle = 0;
            while (true)
            {
                var rval = PInvoke.LsaEnumerateTrustedDomainsEx(policyHandle, ref enumerationHandle, out void* buffer, 131072 /* 128KiB */, out uint countReturned);
                if (rval != NTSTATUS.STATUS_SUCCESS &&
                    (uint)rval != (uint)NTSTATUSInternal.STATUS_MORE_ENTRIES &&
                    (uint)rval != (uint)NTSTATUSInternal.STATUS_NO_MORE_ENTRIES)
                {
                    throw new LsaApiException(rval);
                }

                if ((uint)rval == (uint)NTSTATUSInternal.STATUS_NO_MORE_ENTRIES)
                {
                    break;
                }

                try
                {
                    IntPtr bufptr = new IntPtr(buffer);
                    var span = new Span<TRUSTED_DOMAIN_INFORMATION_EX>(bufptr.ToPointer(), (int)countReturned);
                    foreach (var trustedDomain in span)
                    {
                        trustedDomainList.Add(new LsaTrustedDomain(trustedDomain));
                    }
                }
                finally
                {
                    PInvoke.LsaFreeMemory(buffer);
                }
            }

            return trustedDomainList.ToArray();
        }

        public static unsafe LsaDomainAuthInfo CallLsaQueryTrustedDomainInfoByName(LsaCloseSafeHandle policyHandle, string domainName)
        {
            fixed (char* domainNameLocal = domainName)
            {
                var domainNameLsaString = new LSA_UNICODE_STRING
                {
                    Length = (ushort)(domainName.Length * sizeof(char)),
                    MaximumLength = (ushort)(domainName.Length * sizeof(char)),
                    Buffer = domainNameLocal
                };

                // Only supporting auth information so far -- this could be updated to do more if desired,
                // but you'd have to marshal differently depending on the parameter passed in
                var rval = PInvoke.LsaQueryTrustedDomainInfoByName(policyHandle, domainNameLsaString, TRUSTED_INFORMATION_CLASS.TrustedDomainAuthInformation, out void* buffer);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                try
                {
                    IntPtr bufptr = new IntPtr(buffer);
                    var authInfo = (TRUSTED_DOMAIN_AUTH_INFORMATION)Marshal.PtrToStructure(bufptr, typeof(TRUSTED_DOMAIN_AUTH_INFORMATION))!;
                    return new LsaDomainAuthInfo(authInfo);
                }
                finally
                {
                    PInvoke.LsaFreeMemory(buffer);
                }
            }
        }

        public static unsafe LsaCloseSafeHandle CallLsaOpenTrustedDomainByName(LsaCloseSafeHandle policyHandle, string domainName, uint desiredAccess)
        {
            fixed (char* domainNameLocal = domainName)
            {
                var domainNameLsaString = new LSA_UNICODE_STRING
                {
                    Length = (ushort)(domainName.Length * sizeof(char)),
                    MaximumLength = (ushort)(domainName.Length * sizeof(char)),
                    Buffer = domainNameLocal
                };

                // TODO: I haven't been able to get this to open yet, I think it might require running locally on a domain controller
                LsaCloseSafeHandle domainPolicyHandle;
                var rval = PInvoke.LsaOpenTrustedDomainByName(policyHandle, domainNameLsaString, desiredAccess, out domainPolicyHandle);
                if (rval != NTSTATUS.STATUS_SUCCESS)
                {
                    throw new LsaApiException(rval);
                }

                return domainPolicyHandle;
            }
        }
    }
}
