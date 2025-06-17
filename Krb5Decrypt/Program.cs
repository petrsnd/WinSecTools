using CommandLine;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Petrsnd.WinSecLib;
using Petrsnd.WinSecLib.Extensions;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;

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
        private static string? ComputerSamAccountName;

        private static string? ComputerHostname;

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

        private static void ValidateRunningAsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    throw new InvalidOperationException("This tool must be run as Administrator.");
                }
            }
        }

        private static void ValidatePrerequisites()
        {
            try
            {
                ComputerHostname = System.Net.Dns.GetHostName();
            }
            catch (Exception)
            {
                Console.WriteLine("This computer is not configured to use DNS names, using environment...");
                ComputerHostname = Environment.MachineName;
            }

            using (var policyHandle = LsaApi.OpenPolicyHandle())
            {
                var domainInfo = policyHandle.GetDnsDomainInfo();
                DomainFqdn = domainInfo.DomainDnsName;
                KerberosRealm = DomainFqdn?.ToUpper();
            }

            Console.WriteLine($"Computer Hostname: {ComputerHostname}");
            if (string.IsNullOrEmpty(ComputerHostname))
            {
                throw new InvalidOperationException("Unable to determine the computer hostname.");
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

        private static KerberosCredential GetKerberosCredential(string userPrincipal, SecureString userPassword)
        {
            return new KerberosPasswordCredential(userPrincipal, userPassword.ToInsecureString());
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

        private static KerberosClient? RunKinit(KerberosCredential creds, bool nonInteractive)
        {
            Console.WriteLine($"Attempting to authenticate as {creds}...");
            var client = GetKerberosClient();
            try
            {
                client.Authenticate(creds).Wait();
                Console.WriteLine("SUCCESS");
                return client;
            }
            catch (Exception)
            {
                Console.WriteLine("FAILED");
                if (nonInteractive)
                {
                    throw;
                }

                return null;
            }
        }

        private static void Execute(Krb5DecryptOptions opts)
        {
            try
            {
                ValidateRunningAsAdministrator();
                ValidatePrerequisites();

                string? userPrincipalName = null;
                SecureString? userPassword = null;
                string? machinePassword = opts.MachinePassword;
                KerberosCredential? creds = null;
                KerberosClient? userKerberosClient = null;
                bool nonInteractive = opts.ReadUserPassword;
                if (nonInteractive)
                {
                    Console.WriteLine("Reading user password from STDIN...");
                    userPrincipalName = opts.UserPrincipalName;
                    userPassword = Console.ReadLine()?.ToSecureString();
                    if (userPassword == null)
                    {
                        throw new InvalidOperationException("Failed to obtain user password via STDIN.");
                    }

                    if (string.IsNullOrEmpty(userPrincipalName) || string.IsNullOrEmpty(machinePassword))
                    {
                        throw new InvalidOperationException("You must specify user principal name and machine password via command-line options to use non-interactive mode.");
                    }

                    creds = GetKerberosCredential(userPrincipalName, userPassword);
                    userKerberosClient = RunKinit(creds, nonInteractive);
                }
                else
                {
                    while (userKerberosClient == null)
                    {
                        userPrincipalName = PromptForValueIfNeeded("User principal name [ex. dan@some.domain]", opts.UserPrincipalName);
                        userPassword = PromptForSecret("User password");
                        creds = GetKerberosCredential(userPrincipalName, userPassword);
                        userKerberosClient = RunKinit(creds, nonInteractive);
                    }
                }

                ComputerSamAccountName = DirectoryServicesUtils.GetComputerSamAccountName(ComputerHostname!, DomainFqdn!, userPrincipalName!, userPassword!);
                Console.WriteLine($"Computer SAM account name: {ComputerSamAccountName}");

                var servicePrincipalNames = DirectoryServicesUtils.GetComputerServicePrincipalNames(DomainFqdn!, ComputerSamAccountName!, userPrincipalName!, userPassword!);
                Console.WriteLine($"Computer service principal names: {servicePrincipalNames.Select(spn => $"{Environment.NewLine}  {spn}")}");
                if (opts.ServiceClass != null)
                {
                    var servicePrincipalName = $"{opts.ServiceClass.ToUpper()}/{ComputerHostname}.{DomainFqdn}";
                    Console.WriteLine($"Adding service principal name: {servicePrincipalName}");
                    if (DirectoryServicesUtils.AddComputerServicePrincipalName(servicePrincipalName, DomainFqdn!, ComputerSamAccountName!, userPrincipalName!, userPassword!))
                    {
                        Console.WriteLine("SUCCESS");
                    }
                    else
                    {
                        Console.WriteLine("Already present");
                    }
                }
                else
                {
                    Console.WriteLine("If your desired service principal name is missing, use the -s (--service-class) option to specify the service name (e.g. '-s HTTP').");
                }

                Console.WriteLine("Krb5Decrypt will set a new password for this computer in AD and store it locally.");
                machinePassword = PromptForValueIfNeeded("New machine password", machinePassword);

                Console.WriteLine("Setting new password for computer via kpasswd protocol...");
                userKerberosClient!.SetPassword(creds, ComputerSamAccountName!, DomainFqdn!, machinePassword);
                Console.WriteLine("SUCCESS");

                Console.WriteLine("Storing new password locally on this computer...");
                using (var policyHandle = LsaApi.OpenPolicyHandle())
                {
                    policyHandle.StorePrivateData("$machine.acc", new LsaPrivateData(machinePassword));
                }

                Console.WriteLine("SUCCESS");
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

        private static void Main(string[] args) => Parser.Default.ParseArguments<Krb5DecryptOptions>(args).WithParsed(Execute);
    }
}
