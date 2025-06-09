using System;
using System.Runtime.Versioning;
using System.Security.Principal;
using Windows.Win32.Security.Authentication.Identity;

namespace Petrsnd.WinSecLib
{
    public class LsaDnsDomainInfo
    {
        public LsaDnsDomainInfo(string name, string dnsDomainName, string dnsForestName, Guid domainGuid, SecurityIdentifier sid)
        {
            Name = name;
            DnsDomainName = dnsDomainName;
            DnsForestName = dnsForestName;
            DomainGuid = domainGuid;
            Sid = sid;
        }

        [SupportedOSPlatform("windows5.1.2600")]
        internal unsafe LsaDnsDomainInfo(POLICY_DNS_DOMAIN_INFO lsaDnsDomainInfo)
        {
            Name = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(lsaDnsDomainInfo.Name);
            DnsDomainName = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(lsaDnsDomainInfo.DnsDomainName);
            DnsForestName = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(lsaDnsDomainInfo.DnsForestName);
            DomainGuid = lsaDnsDomainInfo.DomainGuid;
            Sid = Utils.GetSid(lsaDnsDomainInfo.Sid);
        }

        public string? Name {  get; set; }

        public string? DnsDomainName { get; set; }

        public string? DnsForestName { get; set; }

        public Guid? DomainGuid { get; set; }

        public SecurityIdentifier? Sid { get; set; }
    }
}
