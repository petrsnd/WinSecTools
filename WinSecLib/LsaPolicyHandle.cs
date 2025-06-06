using System;
using System.Runtime.Versioning;
using Windows.Win32;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows5.1.2600")]
    public class LsaPolicyHandle : IDisposable
    {
        private LsaCloseSafeHandle _policyHandle;
        private bool _disposedValue;

        internal LsaPolicyHandle(LsaCloseSafeHandle policyHandle)
        {
            _policyHandle = policyHandle;
        }

        public string RetrievePrivateData(string keyName)
        {
            return LsaApiPInvokeHelper.CallLsaRetrievePrivateData(_policyHandle, keyName);
        }

        public void StorePrivateData(string keyName, string privateData)
        {
            LsaApiPInvokeHelper.CallLsaStorePrivateData(_policyHandle, keyName, privateData);
        }

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
