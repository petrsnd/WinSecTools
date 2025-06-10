using CommandLine;
using Petrsnd.WinSecLib;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [Verb("domainTrust", HelpText = "Get domain trust information from LSA")]
    internal class GetTrustedDomainsCommand : CommandBase
    {
        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            using (var lsaPolicyHandle = LsaApi.OpenPolicyHandle())
            {
                var trustedDomains = lsaPolicyHandle.GetDnsTrustedDomains();
                Console.WriteLine(trustedDomains.AsJson());
            }
        }
    }
}
