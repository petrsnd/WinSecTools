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
        private static DirectoryEntry GetComputerDirectoryEntry(string domainName, string computerSamAccountName, string userPrincipalName, SecureString userPassword)
        {
            using (var searchRoot = new DirectoryEntry($"LDAP://{domainName}", userPrincipalName, userPassword.ToInsecureString()))
            {
                using (var searcher = new DirectorySearcher(searchRoot))
                {
                    searcher.Filter = $"(&(objectClass=computer)(sAMAccountName={computerSamAccountName}))";
                    var result = searcher.FindOne();
                    if (result == null)
                    {
                        throw new InvalidOperationException($"Unable to find directory entry for computer '{computerSamAccountName}'.");
                    }

                    return result.GetDirectoryEntry();
                }
            }
        }

        [SupportedOSPlatform("windows")]
        private static List<string> GetServicePrincipalNamesFromDirectoryEntry(DirectoryEntry computerDirectoryEntry)
        {
            var servicePrincipalNames = new List<string>();
            if (computerDirectoryEntry.Properties.Contains("servicePrincipalName"))
            {
                foreach (var spn in computerDirectoryEntry.Properties["servicePrincipalName"])
                {
                    var strSpn = spn.ToString();
                    if (strSpn != null)
                    {
                        servicePrincipalNames.Add(strSpn);
                    }
                }
            }

            return servicePrincipalNames;
        }

        [SupportedOSPlatform("windows")]
        public static string[] GetComputerServicePrincipalNames(string domainName, string computerSamAccountName, string userPrincipalName, SecureString userPassword)
        {
            using (var computerDirectoryEntry = GetComputerDirectoryEntry(domainName, computerSamAccountName, userPrincipalName, userPassword))
            {
                return GetServicePrincipalNamesFromDirectoryEntry(computerDirectoryEntry).ToArray();
            }
        }

        [SupportedOSPlatform("windows")]
        public static bool AddComputerServicePrincipalName(string servicePrincipalName, string domainName, string computerSamAccountName, string userPrincipalName, SecureString userPassword)
        {
            using (var computerDirectoryEntry = GetComputerDirectoryEntry(domainName, computerSamAccountName, userPrincipalName, userPassword))
            {
                var servicePrincipalNames = GetServicePrincipalNamesFromDirectoryEntry(computerDirectoryEntry);
                if (!servicePrincipalNames.Contains(servicePrincipalName))
                {
                    servicePrincipalNames.Add(servicePrincipalName);
                    computerDirectoryEntry.Properties["servicePrincipalName"].Value = servicePrincipalNames;
                    computerDirectoryEntry.CommitChanges();
                }

                return false;
            }
        }
    }
}
