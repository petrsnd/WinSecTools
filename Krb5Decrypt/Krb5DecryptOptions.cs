using CommandLine;

namespace Petrsnd.Krb5Decrypt
{
    internal class Krb5DecryptOptions
    {
        [Option('u', "user-principal-name", Required = false, Default = false,
            HelpText = "Client user principal name [ex. dan@some.domain]")]
        public string? UserPrincipalName { get; set; }

        [Option('p', "read-user-password", Required = false, Default = false,
            HelpText = "Read client password from STDIN, non-interactive mode")]
        public bool ReadUserPassword { get; set; }

        [Option('s', "service-class", Required = false, Default = false,
            HelpText = "Service class portion of service principal name [ex. http/]")]
        public string? ServiceClass { get; set; }

        [Option('P', "machine-password", Required = false, Default = false,
            HelpText = "New password for the computer (changed in AD, stored locally)")]
        public string? MachinePassword { get; set; }
    }
}
