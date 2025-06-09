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

        public LsaPrivateData RetrievePrivateData(string keyName)
        {
            return LsaApiPInvokeHelper.CallLsaRetrievePrivateData(_policyHandle, keyName);
        }

        public void StorePrivateData(string keyName, LsaPrivateData privateData)
        {
            LsaApiPInvokeHelper.CallLsaStorePrivateData(_policyHandle, keyName, privateData);
        }

        public LsaDnsDomainInfo GetDnsDomainInfo()
        {
            // Almost everything is obsolete, so we only support getting PolicyDnsDomainInformation
            return LsaApiPInvokeHelper.CallLsaQueryInformationPolicy(_policyHandle);
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
