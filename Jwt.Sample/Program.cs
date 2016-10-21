using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json.Serialization;
using Unidevel.Jwt;
using Newtonsoft.Json;

namespace Jwt.Sample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var tokenService = new JwtCodecService<FooBarJwtToken>(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            string jwtToken;

            // Encode token

            {
                var fooBarJwtTokenToEncode = new FooBarJwtToken()
                {
                    UserAge = 37, 
                    ExpirationTime = DateTime.UtcNow.AddSeconds(5)
                };

                jwtToken = tokenService.Encode(fooBarJwtTokenToEncode);
            }

            Console.WriteLine($"Encoded token is: {jwtToken}");

            // Decode token

            {
                var fooBarJwtTokenDecoded = tokenService.Decode(jwtToken);
                Console.WriteLine(fooBarJwtTokenDecoded.UserAge); // display transported property
            }

            // Decode token - catch expired exception

            Task.Delay(5500).Wait(); // 5 seconds is expiration time

            try
            {
                var fooBarJwtTokenDecoded = tokenService.Decode(jwtToken);
                Console.WriteLine(fooBarJwtTokenDecoded.UserAge); // display transported property

                // we should never get here, because token has expired
            }
            catch (JwtTokenValidationException ex)
            {
                Console.WriteLine(ex.Message); // as expected
            }

            Console.ReadLine();
        }
    }

    public class FooBarJwtToken : JwtTokenBase
    {
        [JsonProperty("age", Required = Required.Always)]
        public int UserAge { get; set; }
    }
}
