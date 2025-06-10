using Newtonsoft.Json;
using System;
using System.Linq;
using System.Text;

namespace Petrsnd.WinSecLib
{
    public class CharArrayJsonConverter : JsonConverter<char[]>
    {
        public override char[]? ReadJson(JsonReader reader, Type objectType, char[]? existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            if (reader.Value != null)
            {
                var strValue = (string)reader.Value;
                return strValue.Split(' ').Select(s => Convert.ToChar(Convert.ToUInt16(s))).ToArray();
            }

            return null;
        }

        public override void WriteJson(JsonWriter writer, char[]? value, JsonSerializer serializer)
        {
            if (value == null)
            {
                return;
            }

            writer.WriteValue(BitConverter.ToString(Encoding.Unicode.GetBytes(value)).Replace('-', ' '));
        }
    }
}
