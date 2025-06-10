using System;
using System.Runtime.Versioning;
using Windows.Win32;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows5.1.2600")]
    public class LsaDomainPolicyHandle : IDisposable
    {
        private LsaCloseSafeHandle _policyHandle;
        private bool _disposedValue;

        internal LsaDomainPolicyHandle(LsaCloseSafeHandle policyHandle)
        {
            _policyHandle = policyHandle;
        }

        // TODO: This might only work on a domain controller
        //       See LsaApiPInvokeHelper

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _policyHandle.Dispose();
                }

                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
