using CommandLine;
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
        private static KerberosNetHelper? KerberosNetHelper;
        private static string? KeytabPath;
        private static string? EncryptionType;

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

        private static void SetKeytabPath(string path)
        {
            if (Path.IsPathFullyQualified(path))
            {
                KeytabPath = path;
            }
            else
            {
                KeytabPath = Path.Combine(Directory.GetCurrentDirectory(), path);
            }

            Console.WriteLine($"Keytab path: {KeytabPath}");
            if (Path.Exists(KeytabPath))
            {
                Console.WriteLine("Keytab path already exists and will be overwritten");
                File.Delete(KeytabPath);
            }
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

            Console.WriteLine($"Using encryption type: {EncryptionType}");
        }

        private static bool RunKinit(bool nonInteractive)
        {
            Console.WriteLine($"Attempting to authenticate as {KerberosNetHelper!.UserPrincipalName}...");
            try
            {
                KerberosNetHelper!.Kinit();
                Console.WriteLine("SUCCESS");
                return true;
            }
            catch (Exception)
            {
                Console.WriteLine("FAILED");
                if (nonInteractive)
                {
                    throw;
                }

                return false;
            }
        }

        private static string[] SetServicePrincipalName(string? serviceClass, string userPrincipalName, SecureString userPassword)
        {
            var servicePrincipalNames = DirectoryServicesUtils.GetComputerServicePrincipalNames(DomainFqdn!, ComputerSamAccountName!, userPrincipalName!, userPassword!);
            Console.WriteLine($"Computer service principal names:{Environment.NewLine}{string.Join(Environment.NewLine, servicePrincipalNames.Select(spn => $"  {spn}"))}");
            if (serviceClass != null)
            {
                var servicePrincipalName = $"{serviceClass.ToUpper()}/{ComputerHostname}.{DomainFqdn}";
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
                Console.WriteLine("If your desired service principal name is missing,");
                Console.WriteLine("  use the -s (--service-class) option to specify the service name (e.g. '-s HTTP').");
            }

            // return the new list directly from the directory
            return DirectoryServicesUtils.GetComputerServicePrincipalNames(DomainFqdn!, ComputerSamAccountName!, userPrincipalName!, userPassword);
        }

        private static void SetComputerPassword(string machinePassword)
        {
            Console.WriteLine("Setting new password for computer via kpasswd protocol...");
            KerberosNetHelper!.SetComputerPassword(ComputerSamAccountName!, DomainFqdn!, machinePassword);
            Console.WriteLine("SUCCESS");

            Console.WriteLine("Storing new password locally on this computer...");
            using (var policyHandle = LsaApi.OpenPolicyHandle())
            {
                policyHandle.StorePrivateData("$machine.acc", new LsaPrivateData(machinePassword));
            }

            Console.WriteLine("SUCCESS");
        }

        private static void Execute(Krb5DecryptOptions opts)
        {
            try
            {
                EncryptionType = opts.EncryptionType!.ToLower().Replace('-', '_');

                ValidateRunningAsAdministrator();
                ValidatePrerequisites();

                string? userPrincipalName = null;
                SecureString? userPassword = null;
                string? machinePassword = opts.MachinePassword;
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

                    KerberosNetHelper = new KerberosNetHelper(KerberosRealm!, userPrincipalName, userPassword);
                    RunKinit(nonInteractive);
                }
                else
                {
                    bool authenticated = false;
                    while (!authenticated)
                    {
                        userPrincipalName = PromptForValueIfNeeded("User principal name [ex. dan@some.domain]", opts.UserPrincipalName);
                        userPassword = PromptForSecret("User password");
                        KerberosNetHelper = new KerberosNetHelper(KerberosRealm!, userPrincipalName, userPassword);
                        authenticated = RunKinit(nonInteractive);
                    }
                }

                KerberosNetHelper!.ValidateEncryptionType(EncryptionType!);
                ComputerSamAccountName = DirectoryServicesUtils.GetComputerSamAccountName(ComputerHostname!, DomainFqdn!, userPrincipalName!, userPassword!);
                Console.WriteLine($"Computer SAM account name: {ComputerSamAccountName}");

                var servicePrincipalNames = SetServicePrincipalName(opts.ServiceClass, userPrincipalName!, userPassword!);

                Console.WriteLine("Krb5Decrypt will set a new password for this computer in AD and store it locally.");
                machinePassword = PromptForValueIfNeeded("New machine password", machinePassword);

                SetComputerPassword(machinePassword);

                SetKeytabPath(opts.KeytabFile!);
                Console.WriteLine("Generating the keytab file...");
                KerberosNetHelper!.GenerateKeytab(servicePrincipalNames, ComputerSamAccountName, machinePassword, EncryptionType!, KeytabPath!);
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
