using CommandLine;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Petrsnd.WinSecLib;
using Petrsnd.WinSecLib.Extensions;
using System.Runtime.Versioning;
using System.Security;

namespace Petrsnd.Krb5Decrypt
{
    [SupportedOSPlatform("windows5.1.2600")]
    internal class Program
    {
        private const string preamble = @"
Krb5Decrypt runs as a wizard with steps as it prompts for and verifies inputs.
You may specify command-line options for all values and skip the wizard, but
only the user password may be kept secret via reading from STDIN. It is
assumed that the value for the computer password is known to be insecure and
should be rotated to an unknown value after testing.
";

        private static string? ComputerFqdn;

        private static string? DomainFqdn;

        private static string? KerberosRealm;

        private static string? Prompt(string name)
        {
            Console.Write($"{name}: ");
            return Console.ReadLine();
        }

        private static string PromptForValueIfNeeded(string name, string? value)
        {
            while (string.IsNullOrEmpty(value))
            {
                value = Prompt(name);
            }

            return value;
        }

        private static SecureString PromptForSecret(string name)
        {
            Console.Write($"{name}: ");
            var password = new SecureString();
            while (true)
            {
                var keyInput = Console.ReadKey(true);
                if (keyInput.Key == ConsoleKey.Enter)
                    break;
                if (keyInput.Key == ConsoleKey.Backspace)
                {
                    if (password.Length <= 0)
                        continue;
                    password.RemoveAt(password.Length - 1);
                    Console.Write("\b \b");
                }
                else
                {
                    password.AppendChar(keyInput.KeyChar);
                    Console.Write("*");
                }
            }
            Console.Write(Environment.NewLine);
            return password;
        }

        private static void ValidatePrerequisites()
        {
            Console.WriteLine($"Computer FQDN: {ComputerFqdn}");
            if (string.IsNullOrEmpty(ComputerFqdn))
            {
                throw new InvalidOperationException("Unable to determine the computer FQDN.");
            }

            Console.WriteLine($"Domain FQDN: {DomainFqdn}");
            if (string.IsNullOrEmpty(DomainFqdn))
            {
                throw new InvalidOperationException("Unable to determine the domain FQDN, is this machine joined?");
            }

            Console.WriteLine($"Kerberos realm: {KerberosRealm}");
            if (string.IsNullOrEmpty(KerberosRealm))
            {
                throw new InvalidOperationException("Unable to determine the Kerberos realm, is this machine joined?");
            }
        }

        private static KerberosClient GetKerberosClient()
        {
            var krb5Conf = new Krb5Config
            {
                Defaults =
                    {
                        DefaultRealm = KerberosRealm,
                        DefaultCCacheName = "MEMORY:",
                    },
            };
            return new KerberosClient(krb5Conf);
        }

        private static void Execute(Krb5DecryptOptions opts)
        {
            try
            {
                ComputerFqdn = SysInfoApi.GetComputerDnsFullyQualified();
                using (var policyHandle = LsaApi.OpenPolicyHandle())
                {
                    DomainFqdn = policyHandle.GetDnsDomainInfo().DomainDnsName;
                    KerberosRealm = DomainFqdn?.ToUpper();
                }

                ValidatePrerequisites();

                var client = GetKerberosClient();

                SecureString? userPassword = null;
                if (opts.ReadUserPassword)
                {
                    Console.WriteLine("Reading user password from STDIN...");
                    userPassword = Console.ReadLine()?.ToSecureString();
                    if (userPassword == null)
                    {
                        throw new InvalidOperationException("Failed to obtain user password via STDIN.");
                    }

                    if (string.IsNullOrEmpty(opts.UserPrincipalName) || string.IsNullOrEmpty(opts.MachinePassword))
                    {
                        throw new InvalidOperationException("You must specify user principal name and machine password via command-line options to use non-interactive mode.");
                    }
                }

                var userPrincipal = PromptForValueIfNeeded("User principal name [ex. dan@some.domain]", opts.UserPrincipalName);
                // This makes the prompting feel better to have this after the user principal name
                if (userPassword == null)
                {
                    userPassword = PromptForSecret("User password");
                }

                Console.WriteLine($"Attempting to authenticate as {userPrincipal}...");
                var creds = new KerberosPasswordCredential(userPrincipal, userPassword.ToInsecureString());
                client.Authenticate(creds).Wait();


            }
            catch (Exception ex) when (ex is Win32ErrorException || ex is LsaApiException || ex is NetApiException)
            {
                Console.WriteLine(ex.Message);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fatal exception occurred.");
                Console.WriteLine(ex);
                Environment.Exit(1);
            }
        }

        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Krb5DecryptOptions>(args)
                .WithParsed<Krb5DecryptOptions>(Execute);
        }
    }
}
