using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Petrsnd.WinSecLib.Extensions;
using System.Security;

namespace Petrsnd.Krb5Decrypt
{
    internal class KerberosNetHelper
    {
        public KerberosNetHelper(string kerberosRealm, string userPrincipalName, SecureString userPassword)
        {
            KerberosRealm = kerberosRealm;
            UserPrincipalName = userPrincipalName;
            Krb5Conf = new Krb5Config
            {
                Defaults =
                    {
                        DefaultRealm = KerberosRealm,
                        DefaultCCacheName = "MEMORY:",
                    },
            };
            Creds = new KerberosPasswordCredential(UserPrincipalName, userPassword.ToInsecureString());
            Client = new KerberosClient(Krb5Conf);
        }

        public void Kinit()
        {
            Client.Authenticate(Creds).Wait();
        }

        public void SetComputerPassword(string computerSamAccountName, string domainFqdn, string computerPassword)
        {
            Client.SetPassword(Creds, computerSamAccountName, domainFqdn, computerPassword);
        }

        public string KerberosRealm { get; set; }

        public string UserPrincipalName { get; set; }

        private Krb5Config Krb5Conf { get; set; }

        private KerberosClient Client { get; set; }

        private KerberosCredential Creds { get; set; }
    }
}
