using System;
using System.Runtime.Versioning;

namespace Petrsnd.WinSecLib
{
    public static class LsaApi
    {
        [Flags]
        public enum AccessMask : uint
        {
            PolicyViewLocalInformation = 0x00000001,
            PolicyViewAuditInformation = 0x00000002,
            PolicyGetPrivateInformation = 0x00000004,
            PolicyTrustAdmin = 0x00000008,
            PolicyCreateAccount = 0x00000010,
            PolicyCreateSecret = 0x00000020,
            PolicyCreatePrivilege = 0x00000040,
            PolicySetDefaultQuotaLimits = 0x00000080,
            PolicySetAuditRequirements = 0x00000100,
            PolicyAuditLogAdmin = 0x00000200,
            PolicyServerAdmin = 0x00000400,
            PolicyLookupNames = 0x00000800,
            PolicyNotification = 0x00001000,
            // specific and standard rights
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            Synchronize = 0x00100000,
            StandardRightsRequired = 0x000F0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x001F0000,
            SpecificRightsAll = 0x0000FFFF,
            // combinations
            PolicyAllAccess =
                StandardRightsRequired |
                PolicyViewLocalInformation |
                PolicyViewAuditInformation |
                PolicyGetPrivateInformation |
                PolicyTrustAdmin |
                PolicyCreateAccount |
                PolicyCreateSecret |
                PolicyCreatePrivilege |
                PolicySetDefaultQuotaLimits |
                PolicySetAuditRequirements |
                PolicyAuditLogAdmin |
                PolicyServerAdmin |
                PolicyLookupNames,
            PolicyRead =
                StandardRightsRead |
                PolicyViewAuditInformation |
                PolicyGetPrivateInformation,
            PolicyWrite =
                StandardRightsWrite |
                PolicyTrustAdmin |
                PolicyCreateAccount |
                PolicyCreateSecret |
                PolicyCreatePrivilege |
                PolicySetDefaultQuotaLimits |
                PolicySetAuditRequirements |
                PolicyAuditLogAdmin |
                PolicyServerAdmin,
            PolicyExecute =
                StandardRightsExecute |
                PolicyViewLocalInformation |
                PolicyLookupNames,
        }

        [SupportedOSPlatform("windows5.1.2600")]
        public static LsaPolicyHandle OpenPolicyHandle(string? systemName = null, AccessMask desiredAccess = AccessMask.PolicyAllAccess)
        {
            var policyHandle = LsaApiPInvokeHelper.CallLsaOpenPolicy(systemName, (uint)desiredAccess);
            return new LsaPolicyHandle(policyHandle);
        }
    }
}
