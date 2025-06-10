using System;
using System.Runtime.Versioning;
using System.Security.Principal;
using Windows.Win32.Security.Authentication.Identity;

namespace Petrsnd.WinSecLib
{
    public enum TrustDirection: uint
    {
        Disabled = TRUSTED_DOMAIN_TRUST_DIRECTION.TRUST_DIRECTION_DISABLED,
        InBound = TRUSTED_DOMAIN_TRUST_DIRECTION.TRUST_DIRECTION_INBOUND,
        OutBound = TRUSTED_DOMAIN_TRUST_DIRECTION.TRUST_DIRECTION_OUTBOUND,
        BiDirectional = TRUSTED_DOMAIN_TRUST_DIRECTION.TRUST_DIRECTION_BIDIRECTIONAL,
    }

    public enum TrustType: uint
    {
        PreWindows2000 = TRUSTED_DOMAIN_TRUST_TYPE.TRUST_TYPE_DOWNLEVEL,
        PostWindows2000 = TRUSTED_DOMAIN_TRUST_TYPE.TRUST_TYPE_UPLEVEL,
        Mit = TRUSTED_DOMAIN_TRUST_TYPE.TRUST_TYPE_MIT,
        Dce = TRUSTED_DOMAIN_TRUST_TYPE.TRUST_TYPE_DCE,
    }

    public enum TrustAttributes: uint
    {
        NonTransitive = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_NON_TRANSITIVE,
        PostWindows2000Only = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_UPLEVEL_ONLY,
        FilterSids = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_FILTER_SIDS,
        ForestTransitive = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_FOREST_TRANSITIVE,
        CrossOrganizational = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_CROSS_ORGANIZATION,
        TreatAsExternal = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL,
        WithinForest = TRUSTED_DOMAIN_TRUST_ATTRIBUTES.TRUST_ATTRIBUTE_WITHIN_FOREST,
    }

    public class LsaTrustedDomain
    {
        [SupportedOSPlatform("windows5.1.2600")]
        internal unsafe LsaTrustedDomain(TRUSTED_DOMAIN_INFORMATION_EX trustedDomain)
        {
            Name = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(trustedDomain.Name);
            FlatName = LsaApiPInvokeHelper.ConvertLsaUnicodeStringToString(trustedDomain.FlatName);
            Sid = Utils.GetSid(trustedDomain.Sid);
            Direction = (TrustDirection)trustedDomain.TrustDirection;
            Type = (TrustType)trustedDomain.TrustType;
            Attributes = (TrustAttributes)trustedDomain.TrustAttributes;
        }

        public string? Name { get; private set; }

        public string? FlatName { get; private set; }

        public SecurityIdentifier? Sid { get; private set; }

        public TrustDirection Direction { get; private set; }

        public TrustType Type { get; private set; }

        public TrustAttributes Attributes { get; private set; }
    }
}
