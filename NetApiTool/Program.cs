using CommandLine;
using System.Runtime.Versioning;
using Petrsnd.WinSecLib;

namespace Petrsnd.NetApiTool
{
    internal class Program
    {
        [SupportedOSPlatform("windows5.1.2600")]
        private static void Execute(CommandBase command)
        {
            try
            {
                command.Execute();
            }
            catch (NetApiException ex)
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

        [SupportedOSPlatform("windows5.1.2600")]
        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<ChangePasswordCommand, GetUserCommand, EnumUserCommand>(args)
                .WithParsed<ChangePasswordCommand>(Execute)
                .WithParsed<GetUserCommand>(Execute)
                .WithParsed<EnumUserCommand>(Execute);
        }
    }
}
