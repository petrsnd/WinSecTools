using System.Collections.Generic;
using System.Runtime.Versioning;

namespace Petrsnd.WinSecLib.Extensions
{
    static public class JsonExtensions
    {
        [SupportedOSPlatform("windows5.0")]
        public static string? AsJson(this NetApiUserInformation userInformation)
        {
            if (userInformation == null)
            {
                return null;
            }

            return NetApi.JsonSerialize(userInformation);
        }

        [SupportedOSPlatform("windows5.0")]
        public static string? AsJson(this IEnumerable<NetApiUserInformation> userInformations)
        {
            if (userInformations == null)
            {
                return null;
            }

            return NetApi.JsonSerialize(userInformations);
        }

        public static string? AsJson(this LsaDomainAuthInfo domainAuthInfo)
        {
            if (domainAuthInfo == null)
            {
                return null;
            }

            return LsaApi.JsonSerialize(domainAuthInfo);
        }

        public static string? AsJson(this LsaDomainDnsInfo domainDnsInfo)
        {
            if (domainDnsInfo == null)
            {
                return null;
            }

            return LsaApi.JsonSerialize(domainDnsInfo);
        }

        public static string? AsJson(this LsaPrivateData lsaPrivateData)
        {
            if (lsaPrivateData == null)
            {
                return null;
            }

            return LsaApi.JsonSerialize(lsaPrivateData);
        }

        public static string? AsJson(this LsaTrustedDomain trustedDomain)
        {
            if (trustedDomain == null)
            {
                return null;
            }

            return LsaApi.JsonSerialize(trustedDomain);
        }

        public static string? AsJson(this IEnumerable<LsaTrustedDomain> trustedDomains)
        {
            if (trustedDomains == null)
            {
                return null;
            }

            return LsaApi.JsonSerialize(trustedDomains);
        }
    }
}
