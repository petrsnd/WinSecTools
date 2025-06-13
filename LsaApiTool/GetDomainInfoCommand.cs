using CommandLine;
using Petrsnd.WinSecLib;
using Petrsnd.WinSecLib.Extensions;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [Verb("domainAuth", HelpText = "Get primary domain auth information from LSA")]
    internal class GetDomainInfoCommand : CommandBase
    {
        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            using (var lsaPolicyHandle = LsaApi.OpenPolicyHandle())
            {
                Console.WriteLine(lsaPolicyHandle.GetDomainAuthData().AsJson());
            }
        }
    }
}
