using CommandLine;
using Petrsnd.WinSecLib;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [Verb("domainInfo", HelpText = "Store private data in LSA")]
    internal class GetDnsDomainInfoCommand : CommandBase
    {
        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            using (var lsaPolicyHandle = LsaApi.OpenPolicyHandle())
            {
                var domainInfo = lsaPolicyHandle.GetDnsDomainInfo();
                Console.WriteLine($"NAME: {domainInfo.Name}");
                Console.WriteLine($"DOMAIN DNS: {domainInfo.DnsDomainName}");
                Console.WriteLine($"FOREST DNS: {domainInfo.DnsForestName}");
                Console.WriteLine($"DOMAIN GUID: {domainInfo.DomainGuid}");
                Console.WriteLine($"DOMAIN SID: {domainInfo.Sid?.ToString()}");
            }
        }
    }
}
