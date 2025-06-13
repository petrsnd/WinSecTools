# Petrsnd -- Krb5Decrypt

The purpose of this tool is to generate a Kerberos keytab file with the keys
necessary to decrypt both sides of a Kerberized application protocol. Client /
server applications often use GSS-API (with or without SPNEGO) to add Kerberos
security features to their protocols. Example protocols would be HTTP, LDAP,
or WinRM.

In order to decrypt all the messages in both directions, network analysis
tools, such as Wireshark, need to have Kerberos keys for both the client side
(initiator) and the server side (acceptor) of the GSS-API security context.
For Wireshark specifically, all keys must be included in a single Kerberos
keytab file. Most tools used to generate Kerberos keytab files assume a single
security principal per file. Also, for most tools, you usually need to know
the server side password already, because they don't support changing it in
Active Directory or they don't support changing the password Windows has
stored locally for the machine account.

In the context of this tool, we will use user principal to refer to the client
(initiator) and service principal to refer to the server (acceptor).

Krb5Decrypt operates as a wizard and does everything to get you a Kerberos
keytab file that can decerypt Kerberized protocol traffic for a Windows
service running under the machine account:

  1. It generates keytab entries for the client based on a supplied user
     principal name and password (no changes are made in AD to the user
     security principal).
  2. It identifies the machine where it is running and changes the computer
     security principal's password to a value you specify (changes the
     password stored in AD to a known value).
  3. If a service class is specified, it will make sure the service principal
     name is properly set in AD (it is assumed the user principal has rights
     to make this change).
  4. It changes the local storage of the machine account password to match the
     new password in Active Directory (this maintains the trust relationship
     between the Windows machine and AD).
  5. It stores all generated keys in a single keytab file that can be used to
     decrypt Kerberized protocol traffic with Wireshark.

Krb5Decrypt runs as a wizard with steps as it prompts for and verifies inputs.
You may specify command-line options for all values and skip the wizard, but
only the user password may be kept secret via reading from STDIN. It is
assumed that the value for the computer password is known to be insecure and
should be rotated to an unknown value after testing.

Enjoy!
