using CommandLine;
using Petrsnd.WinSecLib;
using System.Runtime.Versioning;

namespace Petrsnd.NetApiTool
{
    [Verb("passwd", HelpText = "Change a local user password")]
    internal class ChangePasswordCommand : CommandBase
    {
        [Option('s', "server", Required = false,
            HelpText = "IP address or hostname of target server")]
        public string? Server { get; set; }

        [Option('u', "username", Required = false,
            HelpText = "Username of the password to change")]
        public string? Username { get; set; }

        [Option('p', "stdin", Required = false, Default = false,
            HelpText = "Read any required password from console stdin")]
        public bool ReadPassword { get; set; }

        [SupportedOSPlatform("windows5.1.2600")]
        public override void Execute()
        {
            var username = HandleUsernamePrompt(Username);
            if (string.IsNullOrEmpty(username))
            {
                throw new InvalidOperationException("You must specify a username.");
            }

            var password = HandlePasswordPrompt(ReadPassword);
            if (password == null)
            {
                throw new InvalidOperationException("You must specify a password.");
            }

            NetApi.ChangeUserPassword(username, password, Server);
            Console.WriteLine("SUCCESS");
        }
    }
}
