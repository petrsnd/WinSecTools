using System.Runtime.Versioning;

namespace Petrsnd.LsaApiTool
{
    [SupportedOSPlatform("windows")]
    internal abstract class CommandBase
    {
        protected CommandBase() { }

        public abstract void Execute();
    }
}
