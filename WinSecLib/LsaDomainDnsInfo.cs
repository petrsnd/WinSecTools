using System;
using System.Runtime.Versioning;
using System.Security.Principal;
using Windows.Win32.Security.Authentication.Identity;

namespace Petrsnd.WinSecLib
{
    public class LsaDomainDnsInfo
    {
        [SupportedOSPlatform("windows5.1.2600")]
        internal unsafe LsaDomainDnsInfo(POLICY_DNS_DOMAIN_INFO lsaDnsDomainInfo)
        {
            NetBiosName = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(lsaDnsDomainInfo.Name);
            DomainDnsName = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(lsaDnsDomainInfo.DnsDomainName);
            ForestDnsName = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(lsaDnsDomainInfo.DnsForestName);
            DomainGuid = lsaDnsDomainInfo.DomainGuid;
            Sid = Utils.GetSid(lsaDnsDomainInfo.Sid);
        }

        public string? NetBiosName {  get; private set; }

        public string? DomainDnsName { get; private set; }

        public string? ForestDnsName { get; private set; }

        public Guid? DomainGuid { get; private set; }

        public SecurityIdentifier? Sid { get; private set; }
    }
}
