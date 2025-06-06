using CommandLine;
using Petrsnd.WinSecLib;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [Verb("retrieve", HelpText = "Retrieve private data from LSA")]
    internal class RetrievePrivateDataCommand : CommandBase
    {
        [Option('k', "keyname", Required = true,
            HelpText = "Key name of the private data to retrieve")]
        public string? KeyName { get; set; }

        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            using (var lsaPolicyHandle = LsaApi.OpenPolicyHandle())
            {
                var privateData = lsaPolicyHandle.RetrievePrivateData(KeyName!);
                Console.WriteLine($"LENGTH: {privateData.Length}, BYTE_LENGTH: {privateData.LengthInBytes}");
                Console.WriteLine($"STRING: {privateData.ToString()}");
                Console.WriteLine($"HEXVAL: {privateData.ToHexString()}");
            }
        }
    }
}
