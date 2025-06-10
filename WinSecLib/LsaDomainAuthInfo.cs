using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Versioning;
using Windows.Win32.Security.Authentication.Identity;

namespace Petrsnd.WinSecLib
{
    public class LsaAuthData
    {
        internal LsaAuthData(DateTimeOffset lastUpdatetime, string? passwordData)
        {
            LastUpdateTime = lastUpdatetime;
            PasswordData = passwordData;
        }

        internal unsafe LsaAuthData(LSA_AUTH_INFORMATION authInfo)
        {
            LastUpdateTime = DateTimeOffset.FromFileTime(authInfo.LastUpdateTime);
            PasswordData = new string((char*)authInfo.AuthInfo, 0, (int)authInfo.AuthInfoLength);
        }

        public DateTimeOffset LastUpdateTime { get; private set; }

        public string? PasswordData { get; private set; }

        public override string ToString()
        {
            return $"{LastUpdateTime.ToString("o", CultureInfo.InvariantCulture)}:{PasswordData}";
        }
    }

    public class LsaDomainAuthInfo
    {
        [SupportedOSPlatform("windows5.1.2600")]
        internal unsafe LsaDomainAuthInfo(TRUSTED_DOMAIN_AUTH_INFORMATION lsaDomainAuthInfo)
        {
            IncomingAuth = new LsaAuthData[lsaDomainAuthInfo.IncomingAuthInfos];
            IncomingAuthPrevious = new LsaAuthData[lsaDomainAuthInfo.IncomingAuthInfos];
            for (var i = 0; i < lsaDomainAuthInfo.IncomingAuthInfos; i++)
            {
                IncomingAuth[i] = new LsaAuthData(lsaDomainAuthInfo.IncomingAuthenticationInformation[i]);
                IncomingAuthPrevious[i] = new LsaAuthData(lsaDomainAuthInfo.IncomingPreviousAuthenticationInformation[i]);
            }

            OutgoingAuth = new LsaAuthData[lsaDomainAuthInfo.OutgoingAuthInfos];
            OutgoingAuthPrevious = new LsaAuthData[lsaDomainAuthInfo.OutgoingAuthInfos];
            for (var i = 0; i < lsaDomainAuthInfo.IncomingAuthInfos; i++)
            {
                OutgoingAuth[i] = new LsaAuthData(lsaDomainAuthInfo.OutgoingAuthenticationInformation[i]);
                OutgoingAuthPrevious[i] = new LsaAuthData(lsaDomainAuthInfo.OutgoingPreviousAuthenticationInformation[i]);
            }
        }

        public LsaAuthData[] IncomingAuth { get; private set; }

        public LsaAuthData[] IncomingAuthPrevious { get; private set; }

        public LsaAuthData[] OutgoingAuth { get; private set; }

        public LsaAuthData[] OutgoingAuthPrevious { get; private set; }

        public override string ToString()
        {
            return $"INCOMING: {string.Join(',', (IEnumerable<LsaAuthData>)IncomingAuth)}" + Environment.NewLine +
                $"INCOMING PREVIOUS: {string.Join(',', (IEnumerable<LsaAuthData>)IncomingAuthPrevious)}" + Environment.NewLine +
                $"OUTGOING: {string.Join(',', (IEnumerable<LsaAuthData>)OutgoingAuth)}" + Environment.NewLine +
                $"OUTGOING PREVIOUS: {string.Join(',', (IEnumerable<LsaAuthData>)OutgoingAuthPrevious)}";
        }
    }
}
