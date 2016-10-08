using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Tmatic.Tims3.WebApi.Jwt
{
    /// <summary>
    /// Provides coding of JWT Tokens. 
    /// </summary>
    /// <typeparam name="T">Token type. Must inherit JwtTokenBase.</typeparam>
    public interface IJwtEncoder<T> where T: JwtTokenBase
    {
        string Encode(T payload);
    }

    /// <summary>
    /// Provides decoding of JWT Tokens. 
    /// </summary>
    /// <typeparam name="T">Token type. Must inherit JwtTokenBase.</typeparam>
    public interface IJwtDecoder<T> where T: JwtTokenBase
    {
        T Decode(string jwtToken);
    }

    /// <summary>
    /// Base class for all JwtTokens. Inherit and include your own properties. Use JsonProperty attribute
    /// to set short names when possible.
    /// </summary>
    public class JwtTokenBase
    {
        [JsonProperty("exp", NullValueHandling = NullValueHandling.Ignore), JsonConverter(typeof(JwtUnixTimestampJsonConverter))]
        public DateTimeOffset? ExpirationTime { get; set; }
        [JsonProperty("nbf", NullValueHandling = NullValueHandling.Ignore), JsonConverter(typeof(JwtUnixTimestampJsonConverter))]
        public DateTimeOffset? NotBefore { get; set; }
        [JsonProperty("iat", NullValueHandling = NullValueHandling.Ignore), JsonConverter(typeof(JwtUnixTimestampJsonConverter))]
        public DateTimeOffset? IssuedAt { get; set; }
        [JsonProperty("iss", NullValueHandling = NullValueHandling.Ignore)]
        public string Issuer { get; set; }
        [JsonProperty("aud", NullValueHandling = NullValueHandling.Ignore)]
        public string Audience { get; set; }
        [JsonProperty("prn", NullValueHandling = NullValueHandling.Ignore)]
        public string Principal { get; set; }
        [JsonProperty("jti", NullValueHandling = NullValueHandling.Ignore)]
        public string JwtId { get; set; }
        [JsonProperty("typ", NullValueHandling = NullValueHandling.Ignore)]
        public string Typ { get; set; }
    }

    /// <summary>
    /// Used internally to convert UX timestamp dates according to JWT specification.
    /// </summary>
    public class JwtUnixTimestampJsonConverter : JsonConverter
    {
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            long ts = serializer.Deserialize<long>(reader);
            
            return DateTimeOffset.FromUnixTimeSeconds(ts);
        }

        public override bool CanConvert(Type type)
        {
            return typeof(DateTimeOffset).IsAssignableFrom(type);
        }

        public override void WriteJson(
            JsonWriter writer,
            object value,
            JsonSerializer serializer)
        {
            var v = (DateTimeOffset)value;

            var ts = v.ToUnixTimeSeconds();
            writer.WriteRawValue(ts.ToString());
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanWrite
        {
            get
            {
                return true;
            }
        }
    }

    public enum JwtHashAlgorithm
    {
        HS256,
        HS384,
        HS512
    }

    public class JwtTokenValidationException: SecurityException
    {
        public JwtTokenValidationException(string message): base(message)
        {
        }
    }

    public class JwtCodecService<T>: IJwtEncoder<T>, IJwtDecoder<T> where T : JwtTokenBase
    {
        private static readonly IDictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> HashAlgorithms;

        static JwtCodecService()
        {
            HashAlgorithms = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } }
            };
        }

        private Dictionary<string, object> extraHeaders;
        private byte[] key;
        private JwtHashAlgorithm algorithm;

        public JwtCodecService(byte[] key, JwtHashAlgorithm algorithm = JwtHashAlgorithm.HS256, Dictionary<string, object> extraHeaders = null)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            this.key = key;
            this.algorithm = algorithm;
            this.extraHeaders = extraHeaders ?? new Dictionary<string, object>(0); 
        }

        public JwtCodecService(string key, JwtHashAlgorithm algorithm = JwtHashAlgorithm.HS256, Dictionary<string, object> extraHeaders = null) :
            this(Encoding.UTF8.GetBytes(key), algorithm, extraHeaders)
        {
        }

        public string Encode(T payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));

            var header = new Dictionary<string, object>(extraHeaders)
            {
                { "typ", "JWT" },
                { "alg", algorithm.ToString() }
            };

            var headerString = base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            var payloadString = base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));
            var stringToSign = String.Concat(headerString, ".", payloadString);

            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);
            var signature = HashAlgorithms[algorithm](key, bytesToSign);
            var signatureString = base64UrlEncode(signature);

            return String.Concat(stringToSign, ".", signatureString);
        }

        public T Decode(string token)
        {
            if (String.IsNullOrWhiteSpace(token)) throw new ArgumentException("Must not be null, empty or whitespace.", nameof(token));

            var parts = token.Split('.');
            if (parts.Length != 3) throw new ArgumentException("Token must consist from 3 delimited by dot parts", nameof(token));

            var header = parts[0];
            var payload = parts[1];
            var crypto = base64UrlDecode(parts[2]);

            var headerJson = Encoding.UTF8.GetString(base64UrlDecode(header));
            var payloadJson = Encoding.UTF8.GetString(base64UrlDecode(payload));

            var headerData = JsonConvert.DeserializeObject<Dictionary<string, object>>(headerJson);

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
            var alg = (string)headerData["alg"];

            JwtHashAlgorithm algorithm;
            if (!Enum.TryParse(alg, out algorithm)) throw new ArgumentException($"Unknown algorithm '{alg}' used.", nameof(token));

            var signature = HashAlgorithms[algorithm](key, bytesToSign);
            var decodedCrypto = Convert.ToBase64String(crypto);
            var decodedSignature = Convert.ToBase64String(signature);

            if (decodedCrypto != decodedSignature)
            {
#if DEBUG
                throw new JwtTokenValidationException($"Invalid signature. Expected '{decodedCrypto}' got '{decodedSignature}'.");
#else
                throw new JwtTokenValidationException($"Invalid signature. Got '{decodedSignature}' but different expected.");
#endif
            }

            T payloadData = JsonConvert.DeserializeObject<T>(payloadJson);

            if ((payloadData.ExpirationTime.HasValue)&&(payloadData.ExpirationTime < DateTimeOffset.UtcNow)) throw new JwtTokenValidationException($"Token has expired.");
            if ((payloadData.NotBefore.HasValue) && (payloadData.NotBefore > DateTimeOffset.UtcNow)) throw new JwtTokenValidationException($"Token is not yet valid.");

            return payloadData;
        }

        private static string base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        // from JWT spec
        private static byte[] base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break;  // One pad char
                default: throw new Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}
