using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Petrsnd.WinSecLib.Extensions;
using System.Security;
using System.Text;

namespace Petrsnd.Krb5Decrypt
{
    internal class KerberosNetHelper
    {
        public KerberosNetHelper(string kerberosRealm, string userPrincipalName, SecureString userPassword)
        {
            KerberosRealm = kerberosRealm;
            UserPrincipalName = userPrincipalName;
            UserPassword = userPassword;
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

        public void ValidateEncryptionType(string encryptionType)
        {
            if (!Krb5Conf.Defaults.PermittedEncryptionTypes.Select(e => e.ToString().ToLower()).Contains(encryptionType.ToLower()))
            {
                throw new InvalidOperationException("Encryption type must be one of the permitted types");
            }

            if (GetEncryptionType(encryptionType) == null)
            {
                throw new InvalidOperationException($"Unable to parse encryption type for {encryptionType}");
            }
        }

        public void GenerateKeytab(string[] servicePrincipalNames, string computerPassword, string encryptionType, string keytabPath)
        {
            var keytab = new KeyTable();

            // Add the user entry
            var krbPrincipalName = KrbPrincipalName.FromString(UserPrincipalName, PrincipalNameType.NT_PRINCIPAL, KerberosRealm);
            var eType = GetEncryptionType(encryptionType);
            var key = new KerberosKey(
                password: UserPassword.ToInsecureString(),
                principalName: PrincipalName.FromKrbPrincipalName(krbPrincipalName, KerberosRealm),
                salt: GetUserSalt(),
                etype: eType!.Value,
                saltType: SaltType.ActiveDirectoryUser
            );
            keytab.Entries.Add(new KeyEntry(key));

            // Add machine entries (one for each SPN)
            foreach (var spn in servicePrincipalNames)
            {
                krbPrincipalName = KrbPrincipalName.FromString(spn, PrincipalNameType.NT_SRV_HST, KerberosRealm);
                key = new KerberosKey(
                    password: UserPassword.ToInsecureString(),
                    principalName: PrincipalName.FromKrbPrincipalName(krbPrincipalName, KerberosRealm),
                    host: GetServiceHost(spn),
                    salt: GetServiceSalt(spn),
                    etype: eType!.Value,
                    saltType: SaltType.ActiveDirectoryService
                );
                keytab.Entries.Add(new KeyEntry(key));
            }

            // Write keytab
            using (var stream = File.Open(keytabPath, FileMode.Create))
            {
                using (var writer = new BinaryWriter(stream, Encoding.UTF8, false))
                {
                    keytab.Write(writer);
                }
            }
        }

        public string KerberosRealm { get; set; }

        public string UserPrincipalName { get; set; }

        private SecureString UserPassword { get; }

        private Krb5Config Krb5Conf { get; set; }

        private KerberosClient Client { get; set; }

        private KerberosCredential Creds { get; set; }

        private EncryptionType? GetEncryptionType(string encryptionType)
        {
            try
            {
                return (EncryptionType)Enum.Parse(typeof(EncryptionType), encryptionType, ignoreCase: true);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private string GetUserSalt()
        {
            var simpleName = UserPrincipalName.Split('@')[0];
            return $"{KerberosRealm}{simpleName}";
        }

        private string GetServiceSalt(string servicePrincipalName)
        {
            var parts = servicePrincipalName.Split('/');
            var serviceClass = parts[0];
            var hostName = parts[1];
            return $"{KerberosRealm}{serviceClass}{hostName}";
        }
        private string GetServiceHost(string servicePrincipalName)
        {
            var parts = servicePrincipalName.Split('/');
            return parts[1];
        }
    }
}
