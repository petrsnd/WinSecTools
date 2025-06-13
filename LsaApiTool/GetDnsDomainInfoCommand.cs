using CommandLine;
using Petrsnd.WinSecLib;
using Petrsnd.WinSecLib.Extensions;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [Verb("domainDns", HelpText = "Get primary domain DNS information from LSA")]
    internal class GetDnsDomainInfoCommand : CommandBase
    {
        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            using (var lsaPolicyHandle = LsaApi.OpenPolicyHandle())
            {
                var domainInfo = lsaPolicyHandle.GetDnsDomainInfo();
                Console.WriteLine(domainInfo.AsJson());
            }
        }
    }
}
