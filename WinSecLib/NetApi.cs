using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security;
using Windows.Win32.NetworkManagement.NetManagement;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows5.0")]
    public static class NetApi
    {
        static JsonSerializerSettings SerializerSettings { get; }

        static NetApi()
        {
            SerializerSettings = new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                Formatting = Formatting.Indented,
                ReferenceLoopHandling = ReferenceLoopHandling.Serialize,
                Converters = { new SidJsonConverter(), new BitArrayJsonConverter() }
            };
        }

        [Flags]
        public enum EnumerationFilterFlags : uint
        {
            AllAccount = 0x00000000,
            ForeignAccount = 0x00000001,
            NormalAccount = 0x00000002,
            InterDomainTrustAccount = 0x00000008,
            WorkstationTrustAccount = 0x00000010,
            ServerTrustAccount = 0x00000020,
        }

        [SupportedOSPlatform("windows5.0")]
        public static NetApiUserInformation[] EnumerateUsers(EnumerationFilterFlags flags = EnumerationFilterFlags.AllAccount, int level = 0, string? server = null)
        {
            var flagsLocal = (NET_USER_ENUM_FILTER_FLAGS)flags;
            return level switch
            {
                0 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_0>(server, flagsLocal),
                1 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_1>(server, flagsLocal),
                2 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_2>(server, flagsLocal),
                3 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_3>(server, flagsLocal),
                10 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_10>(server, flagsLocal),
                11 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_11>(server, flagsLocal),
                20 => NetApiPInvokeHelper.CallNetUserEnum<USER_INFO_20>(server, flagsLocal),
                _ => throw new ArgumentException("Invalid level specified", nameof(level))
            };
        }

        [SupportedOSPlatform("windows5.1.2600")]
        public static NetApiUserInformation GetUser(string username, int level, string? server = null)
        {
            return level switch
            {
                0 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_0>(server, username),
                1 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_1>(server, username),
                2 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_2>(server, username),
                3 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_3>(server, username),
                4 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_4>(server, username),
                10 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_10>(server, username),
                11 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_11>(server, username),
                20 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_20>(server, username),
                23 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_23>(server, username),
                24 => NetApiPInvokeHelper.CallNetUserGetInfo<USER_INFO_24>(server, username),
                _ => throw new ArgumentException("Invalid level specified")
            };
        }

        [SupportedOSPlatform("windows5.0")]
        public static void ChangeUserPassword(string username, SecureString password, string? server = null)
        {
            NetApiPInvokeHelper.CallNetUserSetInfo(server, username, password.ToInsecureString());
        }

        public static string? JsonSerialize(NetApiUserInformation userInformation)
        {
            return JsonConvert.SerializeObject(userInformation, SerializerSettings);
        }

        public static string? JsonSerialize(IEnumerable<NetApiUserInformation> userInformations)
        {
            return JsonConvert.SerializeObject(userInformations, SerializerSettings);
        }
    }
}
