using CommandLine;
using Petrsnd.WinSecLib;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [Verb("store", HelpText = "Store private data in LSA")]
    internal class StorePrivateDataCommand : CommandBase
    {
        [Option('k', "keyname", Required = true,
            HelpText = "Key name of the private data to store")]
        public string? KeyName { get; set; }

        [Option('d', "privatedata", Required = true,
            HelpText = "Private data to store")]
        public string? PrivateData { get; set; }

        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            using (var lsaPolicyHandle = LsaApi.OpenPolicyHandle())
            {
                lsaPolicyHandle.StorePrivateData(KeyName!, new LsaPrivateData(PrivateData!));
                Console.WriteLine("SUCCESS");
            }
        }
    }
}
