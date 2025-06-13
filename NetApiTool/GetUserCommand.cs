using CommandLine;
using Petrsnd.WinSecLib;
using Petrsnd.WinSecLib.Extensions;
using System.Runtime.Versioning;

namespace Petrsnd.NetApiTool
{
    [Verb("user", HelpText = "Get information about a user from the SAM database")]
    internal class GetUserCommand : CommandBase
    {
        [Option('s', "server", Required = false,
            HelpText = "IP address or hostname of target server")]
        public string? Server { get; set; }

        [Option('u', "username", Required = false,
            HelpText = "Username to get information for")]
        public string? Username { get; set; }

        [Option('l', "level", Required = false, Default = 0,
            HelpText = "Information level (values: 0 [default], 1, 2, 3, 4, 10, 11, 20, 23, 24)")]
        public int Level { get; set; }

        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            var username = HandleUsernamePrompt(Username);
            if (string.IsNullOrEmpty(username))
            {
                throw new InvalidOperationException("You must specify a username.");
            }

            var userInformation = NetApi.GetUser(username, Level, Server);
            Console.WriteLine(userInformation.AsJson());
        }
    }
}
