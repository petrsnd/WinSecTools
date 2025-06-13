using System.Runtime.Versioning;
using System.Security;
using Petrsnd.WinSecLib.Extensions;

namespace Petrsnd.NetApiTool
{
    [SupportedOSPlatform("windows5.1.2600")]
    internal abstract class CommandBase
    {
        protected CommandBase() { }

        protected static SecureString PromptForSecret(string name)
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

        protected static SecureString? HandlePasswordPrompt(bool readPassword)
        {
            return readPassword ? Console.ReadLine()?.ToSecureString() : PromptForSecret("Password");
        }

        protected static string? HandleUsernamePrompt(string? username)
        {
            if (!string.IsNullOrEmpty(username))
            {
                return username;
            }
            Console.Write("Username: ");
            return Console.ReadLine();
        }

        public abstract void Execute();
    }
}
