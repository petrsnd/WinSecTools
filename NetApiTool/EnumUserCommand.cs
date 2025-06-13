using CommandLine;
using Petrsnd.WinSecLib;
using Petrsnd.WinSecLib.Extensions;
using System.Runtime.Versioning;

namespace Petrsnd.NetApiTool
{
    [Verb("users", HelpText = "Get information about all users from SAM database")]
    internal class EnumUserCommand : CommandBase
    {
        [Option('s', "server", Required = false,
            HelpText = "IP address or hostname of target server")]
        public string? Server { get; set; }

        [Option('l', "level", Required = false, Default = 0,
            HelpText = "Information level (0, 1, 2, 3, 10, 11, 20)")]
        public int Level { get; set; }

        [Option('f', "filter", Required = false, Default = NetApi.EnumerationFilterFlags.AllAccount,
            HelpText = "Account filter (AllAccount, ForeignAccount, NormalAccount, InterDomainTrustAccount, WorkstationTrustAccount, ServerTrustAccount)")]
        public NetApi.EnumerationFilterFlags Filter { get; set; }

        [SupportedOSPlatform("windows5.0")]
        public override void Execute()
        {
            var userInformations = NetApi.EnumerateUsers(Filter, Level, Server);
            Console.WriteLine(userInformations.AsJson());
        }
    }
}
