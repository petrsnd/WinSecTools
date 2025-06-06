using CommandLine;
using Petrsnd.WinSecLib;
using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
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
            Parser.Default.ParseArguments<StorePrivateDataCommand, RetrievePrivateDataCommand>(args)
                .WithParsed<StorePrivateDataCommand>(Execute)
                .WithParsed<RetrievePrivateDataCommand>(Execute);
        }
    }
}
