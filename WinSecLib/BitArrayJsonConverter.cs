using Newtonsoft.Json;
using System;
using System.Collections;
using System.Linq;

namespace Petrsnd.WinSecLib
{
    public class BitArrayJsonConverter : JsonConverter<BitArray>
    {
        public override BitArray? ReadJson(JsonReader reader, Type objectType, BitArray? existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            if (reader.Value != null)
            {
                var strValue = (string)reader.Value;
                return new BitArray(strValue.Select(c => c == '1').ToArray());
            }

            return null;
        }

        public override void WriteJson(JsonWriter writer, BitArray? value, JsonSerializer serializer)
        {
            if (value == null)
            {
                return;
            }

            writer.WriteValue(string.Join("", value.Cast<bool>().Select(b => b ? "1" : "0")));
        }
    }
}
