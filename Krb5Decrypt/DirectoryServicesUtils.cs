using Petrsnd.WinSecLib.Extensions;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using System.Security;

namespace Petrsnd.Krb5Decrypt
{
    internal static class DirectoryServicesUtils
    {
        [SupportedOSPlatform("windows")]
        public static string GetComputerSamAccountName(string computerHostname, string domainName, string userPrincipalName, SecureString userPassword)
        {
            using (var context = new PrincipalContext(ContextType.Domain, domainName, userPrincipalName, userPassword.ToInsecureString()))
            {
                ComputerPrincipal computer = ComputerPrincipal.FindByIdentity(context, IdentityType.Name, computerHostname);
                if (computer == null)
                {
                    throw new InvalidOperationException($"Unable to find the SAM account name for computer '{computerHostname}'.");
                }

                return computer.SamAccountName;
            }
        }

        [SupportedOSPlatform("windows")]
        public static string[] GetComputerServicePrincipalNames(string domainName, string computerSamAccountName, string userPrincipalName, SecureString userPassword)
        {
            var servicePrincipalNames = new List<string>();
            using (var searchRoot = new DirectoryEntry($"LDAP://{domainName}", userPrincipalName, userPassword.ToInsecureString()))
            {
                using (var searcher = new DirectorySearcher(searchRoot))
                {
                    searcher.Filter = $"(&(objectClass=computer)(sAMAccountName={computerSamAccountName}))";
                    var result = searcher.FindOne();
                    if (result != null)
                    {
                        DirectoryEntry computerEntry = result.GetDirectoryEntry();
                        if (computerEntry.Properties.Contains("servicePrincipalName"))
                        {
                            foreach (var spn in computerEntry.Properties["servicePrincipalName"])
                            {
                                var strSpn = spn.ToString();
                                if (strSpn != null)
                                {
                                    servicePrincipalNames.Add(strSpn);
                                }
                            }
                        }
                    }
                }
            }

            return servicePrincipalNames.ToArray();
        }
    }
}
