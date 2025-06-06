using Newtonsoft.Json;
using System;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Petrsnd.WinSecLib
{
    [SupportedOSPlatform("windows")]
    public class SidJsonConverter : JsonConverter<SecurityIdentifier>
    {
        public override SecurityIdentifier? ReadJson(JsonReader reader, Type objectType, SecurityIdentifier? existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            if (reader.Value != null)
            {
                return new SecurityIdentifier((string)reader.Value);
            }

            return null;
        }

        public override void WriteJson(JsonWriter writer, SecurityIdentifier? value, JsonSerializer serializer)
        {
            writer.WriteValue(value?.ToString());
        }
    }
}
