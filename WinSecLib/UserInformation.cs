using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json.Serialization;
using Windows.Win32;
using Windows.Win32.NetworkManagement.NetManagement;
using Windows.Win32.Security;

namespace Petrsnd.WinSecLib
{
    public enum UserPrivilege : uint
    { 
        Guest = 0U,
        User = 1U,
        Admin = 2U,
    }

    public enum UserAccountFlags : uint
    {
        LoginScriptExecuted = 0x00000001,
        AccountDisabled = 0x00000002,
        HomeDirectoryRequired = 0x00000008,
        NoPasswordRequired = 0x00000020,
        UserCannotChangePassword = 0x00000040,
        AccountLockedOut = 0x00000010,
        PasswordDoesNotExpire = 0x00010000,
        EncryptedPasswordInActiveDirectory = 0x00000080,
        CannotBeDelegated = 0x00100000,
        SmartCardRequired = 0x00040000,
        DesEncryptionOnly = 0x00200000,
        NoPreauthInKerberos = 0x00400000,
        TrustedForDelegation = 0x00080000,
        PasswordIsExpired = 0x00800000,
        TrustedToAuthenticateForDelegation = 0x01000000,
    }

    public enum OperatorPrivileges : uint
    {
        Print = 0x00000001,
        Communications = 0x00000002,
        Server = 0x00000004,
        Accounts = 0x00000008,
    }

    public class UserInformation
    {
        public int Level { get; set; }

        public string? Name { get; set; }

        [JsonConverter(typeof(SidJsonConverter))]
        public SecurityIdentifier? Sid { get; set; }

        public int? Rid { get; set; }

        public int? PrimaryGroupId { get; set; }

        public UserAccountFlags? Flags { get; set; }

        public OperatorPrivileges? OperatorPrivileges { get; set; }

        public UserPrivilege? PrivilegeLevel { get; set; }

        public string? Password { get; set; }

        public TimeSpan? PasswordAge { get; set; }

        public int? PasswordExpired { get; set; }

        public int? BadPasswordCount { get; set; }

        public DateTimeOffset? AccountExpires { get; set; }

        public int? NumLogons { get; set; }

        public DateTimeOffset? LastLogon { get; set; }

        public DateTimeOffset? LastLogoff { get; set; }

        public string? Workstations { get; set; }

        [JsonConverter(typeof(BitArrayJsonConverter))]
        public BitArray? LogonHours { get; set; }

        public string? LogonServer { get; set; }

        public string? HomeDirectory { get; set; }

        public string? HomeDirectoryDrive { get; set; }

        public string? FullName { get; set; }

        public string? Profile { get; set; }

        public string? ScriptPath { get; set; }

        public string? Comment { get; set; }

        public string? UserComment { get; set; }

        public string? Parms { get; set; }

        public uint? MaxStorage { get; set; }

        public uint? UnitsPerWeek { get; set; }

        public int? CountryCode { get; set; }

        public int? CodePage { get; set; }

        public bool IsInternetIdentity { get; set; }

        public string? InternetProviderName { get; set; }

        public string? InternetPrincipalName { get; set; }

        private static unsafe BitArray? GetLogonHours(byte* logonHours)
        {
            if (logonHours != null)
            {
                var byteArray = new byte[21];
                Marshal.Copy((IntPtr)logonHours, byteArray, 0, 21);
                return new BitArray(byteArray);
            }

            return null;
        }

        [SupportedOSPlatform("windows5.1.2600")]
        private static unsafe SecurityIdentifier? GetSid(PSID pSid)
        {
            if (!pSid.IsNull && PInvoke.IsValidSid(pSid))
            {
                var length = PInvoke.GetLengthSid(pSid);
                byte[] sidBytes = new byte[length];
                Marshal.Copy(new IntPtr(pSid), sidBytes, 0, (int)length);
                return new SecurityIdentifier(sidBytes, 0);
            }

            return null;
        }

        internal static UserInformation CreateFrom(USER_INFO_0 userInfo)
        {
            return new UserInformation
            {
                Level = 0,
                Name = userInfo.usri0_name.ToString(),
            };
        }

        internal static UserInformation CreateFrom(USER_INFO_1 userInfo)
        {
            return new UserInformation
            {
                Level = 1,
                Name = userInfo.usri1_name.ToString(),
                // Same as USER_INFO_0 above, USER_INFO_1 Additions below
                Password = userInfo.usri1_password.ToString(),
                PasswordAge = userInfo.usri1_password_age == 0 ? null : TimeSpan.FromSeconds(userInfo.usri1_password_age),
                PrivilegeLevel = (UserPrivilege)userInfo.usri1_priv,
                HomeDirectory = userInfo.usri1_home_dir.ToString(),
                Comment = userInfo.usri1_comment.ToString(),
                Flags = (UserAccountFlags)userInfo.usri1_flags,
                ScriptPath = userInfo.usri1_script_path.ToString(),
            };
        }

        internal static UserInformation CreateFrom(USER_INFO_2 userInfo)
        {
            var userInformation = new UserInformation
            {
                Level = 2,
                Name = userInfo.usri2_name.ToString(),
                Password = userInfo.usri2_password.ToString(),
                PasswordAge = userInfo.usri2_password_age == 0 ? null : TimeSpan.FromSeconds(userInfo.usri2_password_age),
                PrivilegeLevel = (UserPrivilege)userInfo.usri2_priv,
                HomeDirectory = userInfo.usri2_home_dir.ToString(),
                Comment = userInfo.usri2_comment.ToString(),
                Flags = (UserAccountFlags)userInfo.usri2_flags,
                ScriptPath = userInfo.usri2_script_path.ToString(),
                // Same as USER_INFO_1 above, USER_INFO_2 Additions below
                OperatorPrivileges = (OperatorPrivileges)userInfo.usri2_auth_flags,
                FullName = userInfo.usri2_full_name.ToString(),
                UserComment = userInfo.usri2_comment.ToString(),
                Parms = userInfo.usri2_parms.ToString(),
                Workstations = userInfo.usri2_workstations.ToString(),
                LastLogon = userInfo.usri2_last_logon == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri2_last_logon),
                LastLogoff = userInfo.usri2_last_logoff == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri2_last_logoff),
                AccountExpires = userInfo.usri2_acct_expires == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri2_acct_expires),
                MaxStorage = userInfo.usri2_max_storage,
                UnitsPerWeek = userInfo.usri2_units_per_week,
                BadPasswordCount = (int)userInfo.usri2_bad_pw_count,
                NumLogons = (int)userInfo.usri2_num_logons,
                LogonServer = userInfo.usri2_logon_server.ToString(),
                CountryCode = (int)userInfo.usri2_country_code,
                CodePage = (int)userInfo.usri2_code_page,
            };

            unsafe
            {
                userInformation.LogonHours = GetLogonHours(userInfo.usri2_logon_hours);
            }

            return userInformation;
        }

        internal static UserInformation CreateFrom(USER_INFO_3 userInfo)
        {
            var userInformation = new UserInformation
            {
                Level = 3,
                Name = userInfo.usri3_name.ToString(),
                Password = userInfo.usri3_password.ToString(),
                PasswordAge = userInfo.usri3_password_age == 0 ? null : TimeSpan.FromSeconds(userInfo.usri3_password_age),
                PrivilegeLevel = (UserPrivilege)userInfo.usri3_priv,
                HomeDirectory = userInfo.usri3_home_dir.ToString(),
                Comment = userInfo.usri3_comment.ToString(),
                Flags = (UserAccountFlags)userInfo.usri3_flags,
                ScriptPath = userInfo.usri3_script_path.ToString(),
                OperatorPrivileges = (OperatorPrivileges)userInfo.usri3_auth_flags,
                FullName = userInfo.usri3_full_name.ToString(),
                UserComment = userInfo.usri3_comment.ToString(),
                Parms = userInfo.usri3_parms.ToString(),
                Workstations = userInfo.usri3_workstations.ToString(),
                LastLogon = userInfo.usri3_last_logon == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri3_last_logon),
                LastLogoff = userInfo.usri3_last_logoff == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri3_last_logoff),
                AccountExpires = userInfo.usri3_acct_expires == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri3_acct_expires),
                MaxStorage = userInfo.usri3_max_storage,
                UnitsPerWeek = userInfo.usri3_units_per_week,
                BadPasswordCount = (int)userInfo.usri3_bad_pw_count,
                NumLogons = (int)userInfo.usri3_num_logons,
                LogonServer = userInfo.usri3_logon_server.ToString(),
                CountryCode = (int)userInfo.usri3_country_code,
                CodePage = (int)userInfo.usri3_code_page,
                // Same as USER_INFO_2 above, USER_INFO_3 Additions below
                Rid = (int)userInfo.usri3_user_id,
                PrimaryGroupId = (int)userInfo.usri3_primary_group_id,
                Profile = userInfo.usri3_profile.ToString(),
                HomeDirectoryDrive = userInfo.usri3_home_dir_drive.ToString(),
                PasswordExpired = (int)userInfo.usri3_password_expired,
            };

            unsafe
            {
                userInformation.LogonHours = GetLogonHours(userInfo.usri3_logon_hours);
            }

            return userInformation;
        }

        [SupportedOSPlatform("windows5.1.2600")]
        internal static UserInformation CreateFrom(USER_INFO_4 userInfo)
        {
            var userInformation = new UserInformation
            {
                Level = 4,
                Name = userInfo.usri4_name.ToString(),
                Password = userInfo.usri4_password.ToString(),
                PasswordAge = userInfo.usri4_password_age == 0 ? null : TimeSpan.FromSeconds(userInfo.usri4_password_age),
                PrivilegeLevel = (UserPrivilege)userInfo.usri4_priv,
                HomeDirectory = userInfo.usri4_home_dir.ToString(),
                Comment = userInfo.usri4_comment.ToString(),
                Flags = (UserAccountFlags)userInfo.usri4_flags,
                ScriptPath = userInfo.usri4_script_path.ToString(),
                OperatorPrivileges = (OperatorPrivileges)userInfo.usri4_auth_flags,
                FullName = userInfo.usri4_full_name.ToString(),
                UserComment = userInfo.usri4_comment.ToString(),
                Parms = userInfo.usri4_parms.ToString(),
                Workstations = userInfo.usri4_workstations.ToString(),
                LastLogon = userInfo.usri4_last_logon == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri4_last_logon),
                LastLogoff = userInfo.usri4_last_logoff == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri4_last_logoff),
                AccountExpires = userInfo.usri4_acct_expires == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri4_acct_expires),
                MaxStorage = userInfo.usri4_max_storage,
                UnitsPerWeek = userInfo.usri4_units_per_week,
                BadPasswordCount = (int)userInfo.usri4_bad_pw_count,
                NumLogons = (int)userInfo.usri4_num_logons,
                LogonServer = userInfo.usri4_logon_server.ToString(),
                CountryCode = (int)userInfo.usri4_country_code,
                CodePage = (int)userInfo.usri4_code_page,
                // Same as USER_INFO_3, except RID is swapped for SID right here in USER_INFO_4
                PrimaryGroupId = (int)userInfo.usri4_primary_group_id,
                Profile = userInfo.usri4_profile.ToString(),
                HomeDirectoryDrive = userInfo.usri4_home_dir_drive.ToString(),
                PasswordExpired = (int)userInfo.usri4_password_expired,
            };

            unsafe
            {
                userInformation.LogonHours = GetLogonHours(userInfo.usri4_logon_hours);
                userInformation.Sid = GetSid(userInfo.usri4_user_sid);
            }

            return userInformation;
        }

        internal static UserInformation CreateFrom(USER_INFO_10 userInfo)
        {
            return new UserInformation
            {
                Level = 10,
                Name = userInfo.usri10_name.ToString(),
                Comment = userInfo.usri10_comment.ToString(),
                UserComment = userInfo.usri10_comment.ToString(),
                FullName = userInfo.usri10_full_name.ToString(),
            };
        }

        internal static UserInformation CreateFrom(USER_INFO_11 userInfo)
        {
            var userInformation = new UserInformation
            {
                Level = 11,
                Name = userInfo.usri11_name.ToString(),
                Comment = userInfo.usri11_comment.ToString(),
                UserComment = userInfo.usri11_comment.ToString(),
                FullName = userInfo.usri11_full_name.ToString(),
                // Same as USER_INFO_10 above, USER_INFO_11 Additions below
                PrivilegeLevel = (UserPrivilege)userInfo.usri11_priv,
                OperatorPrivileges = (OperatorPrivileges)userInfo.usri11_auth_flags,
                PasswordAge = userInfo.usri11_password_age == 0 ? null : TimeSpan.FromSeconds(userInfo.usri11_password_age),
                HomeDirectory = userInfo.usri11_home_dir.ToString(),
                Parms = userInfo.usri11_parms.ToString(),
                LastLogon = userInfo.usri11_last_logon == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri11_last_logon),
                LastLogoff = userInfo.usri11_last_logoff == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(userInfo.usri11_last_logoff),
                BadPasswordCount = (int)userInfo.usri11_bad_pw_count,
                NumLogons = (int)userInfo.usri11_num_logons,
                LogonServer = userInfo.usri11_logon_server.ToString(),
                CountryCode = (int)userInfo.usri11_country_code,
                Workstations = userInfo.usri11_workstations.ToString(),
                MaxStorage = userInfo.usri11_max_storage,
                UnitsPerWeek = userInfo.usri11_units_per_week,
                CodePage = (int)userInfo.usri11_code_page,
            };

            unsafe
            {
                userInformation.LogonHours = GetLogonHours(userInfo.usri11_logon_hours);
            }

            return userInformation;
        }

        internal static UserInformation CreateFrom(USER_INFO_20 userInfo)
        {
            return new UserInformation
            {
                Level = 20,
                Name = userInfo.usri20_name.ToString(),
                FullName = userInfo.usri20_full_name.ToString(),
                Comment = userInfo.usri20_comment.ToString(),
                Flags = (UserAccountFlags)userInfo.usri20_flags,
                Rid = (int)userInfo.usri20_user_id,
            };
        }

        [SupportedOSPlatform("windows5.1.2600")]
        internal static UserInformation CreateFrom(USER_INFO_23 userInfo)
        {
            var userInformation = new UserInformation
            {
                Level = 23,
                Name = userInfo.usri23_name.ToString(),
                FullName = userInfo.usri23_full_name.ToString(),
                Comment = userInfo.usri23_comment.ToString(),
                Flags = (UserAccountFlags)userInfo.usri23_flags,
            };

            unsafe
            {
                userInformation.Sid = GetSid(userInfo.usri23_user_sid);
            }

            return userInformation;
        }

        [SupportedOSPlatform("windows5.1.2600")]
        internal static UserInformation CreateFrom(USER_INFO_24 userInfo)
        {
            var userInformation = new UserInformation
            {
                Level = 24,
                IsInternetIdentity = userInfo.usri24_internet_identity,
                Flags = (UserAccountFlags)userInfo.usri24_flags,
                InternetProviderName = userInfo.usri24_internet_provider_name.ToString(),
                InternetPrincipalName = userInfo.usri24_internet_principal_name.ToString(),
            };

            unsafe
            {
                userInformation.Sid = GetSid(userInfo.usri24_user_sid);
            }

            return userInformation;
        }
    }
}
