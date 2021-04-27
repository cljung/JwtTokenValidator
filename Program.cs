using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;

namespace JwtTokenValidator
{
    class Program
    {
        private byte[] privateSigningKey = Encoding.ASCII.GetBytes("This-is-my-magic-private-secret-that-will-be-used-to-sign-a-private-JWT");
        private string issuer = "http://consoleprogram";
        private string audience = "who-ever-I-send-it-too";

        private string wellKnownOidcConfigurationEndpoint = "https://cljungdemob2c.b2clogin.com/cljungdemob2c.onmicrosoft.com/B2C_1A_UX_signup_signin/v2.0/.well-known/openid-configuration";
        private JObject b2cJwksConfig;
        private string b2cIssuer;
        private string b2cToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJxOFlPUkRNbGZsdkZDbVVIVEtnam5hOW02akJHZWtqRW9KdEVvX2JyekEifQ.eyJleHAiOjE2MTk1MzMyMTIsIm5iZiI6MTYxOTUzMjg1MiwidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9jbGp1bmdkZW1vYjJjLmIyY2xvZ2luLmNvbS9iNmMxMTE4My1mYzY2LTQ5MzctODZmZS05OGE3YWYzMWEwMjMvdjIuMC8iLCJzdWIiOiIzNGM5YWRhZS01NmY4LTRmNGItYTE3Ni1mYmM2MGQzY2MzNTUiLCJhdWQiOiJkNjM2YmViNC1lMGM1LTRjNWUtOWJiMC1kMmZkNGUxZjk1MjUiLCJhY3IiOiJiMmNfMWFfdXhfc2lnbnVwX3NpZ25pbiIsIm5vbmNlIjoiZGI3ODk1ZWEtODllMi00YTI5LTg1YjEtMTYzOWFhOTkzMzIwIiwiaWF0IjoxNjE5NTMyODUyLCJhdXRoX3RpbWUiOjE2MTk1MzI4NTIsImVtYWlsIjoiY2xqdW5nZGVtb0BvdXRsb29rLmNvbSIsIm5hbWUiOiJDaHJpc3RlciBManVuZyAoZGVtbykiLCJnaXZlbl9uYW1lIjoiQ2hyaXN0ZXIiLCJmYW1pbHlfbmFtZSI6IkxqdW5nIiwidGlkIjoiYjZjMTExODMtZmM2Ni00OTM3LTg2ZmUtOThhN2FmMzFhMDIzIn0.YiXu0rvuH6Gq6Z3Bn3aXYIROBLtoRgDd9pjytRFCwvJE7VWV3dLDmtpC0tnGVqUmXquBFACQaGsOHjcVUNMrFGNjl4h4tIt69iKedTrECm42-7ee_s5Z3VT9ssgelz7s16jTu5IAxuL6OaRmqgX0dqgq67L7GN1ORFzyb0XGgMauWfqYHBLpwJoYm89TETWAcrcnjeus6g9FldyxEVXzJZ9lx6TmGHoNgQBJ-GEArQiDgc7kSrV85Xi98uJBVjPOvFtZUzYjugmUYHEMY_qgpzybkYsKbS47aExMVmTRl9Mo_2BnYTZX6CmAjvdp2Q6rRKo8ygb9R7FpJ4K_WtayJQ";
        private string b2cAudience = "d636beb4-e0c5-4c5e-9bb0-d2fd4e1f9525";

        static void Main(string[] args)
        {
            Program p = new Program();
            p.Go(args);
        }
        public void Go(string[] args)
        {
            Console.WriteLine("--- Self-signed JWT ---\n");

            string id = Guid.NewGuid().ToString();
            Console.WriteLine("*** Generate a self-signed JWT token ***");
            string jwtToken = GenerateJwtToken( "id", id, privateSigningKey );
            Console.WriteLine( jwtToken );
            ValidateJwtToken( jwtToken, issuer, audience, privateSigningKey );

            Console.WriteLine("\n --- Azure AD B2C ---\n\n{0}\n", b2cToken);

            if ( LoadB2CMetadata( wellKnownOidcConfigurationEndpoint ) ) {
                bool isValid = ValidateJwtToken(b2cToken, b2cIssuer, b2cAudience, null);
            }
        }
        // Generate a self signed JWT token
        public string GenerateJwtToken( string claimName, string claimValue, byte[] signingKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim( claimName, claimValue ) }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public JObject GetJwtPart(string jwtToken, int part)
        {
            if (!(part == 0 || part == 1))
                throw new ArgumentOutOfRangeException("part", "Must be 0 or 1");
            string[] parts = jwtToken.Split(".");
            parts[part] = parts[part].PadRight(4 * ((parts[part].Length + 3) / 4), '=');
            return JObject.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(parts[part])));
        }

        // Parse the JWT header into a JObject
        public JObject GetJwtHeader( string jwtToken )
        {
            return GetJwtPart(jwtToken, 0);
        }
        public JObject GetJwtPayload(string jwtToken)
        {
            return GetJwtPart(jwtToken, 1);
        }
        // Create a Json Web Key for the JWT token based on the JWKS from the .well-known/openid-configuration metadata 
        public JsonWebKey CreateJsonWebKey( string kid )
        {
            JsonWebKey jwk = null;
            // find matching 'kid' in metadata from jwks_uri
            foreach (var key in this.b2cJwksConfig["keys"]) {
                if (key["kid"].ToString() == kid ) {
                    jwk = new JsonWebKey() {
                        Kid = key["kid"].ToString(),
                        Kty = key["kty"].ToString(),
                        E = key["e"].ToString(),
                        N = key["n"].ToString()
                    };
                }
            }
            return jwk;
        }
        // Validate a JWT token that is either self signed or issued+signed by an OIDC provider
        public bool ValidateJwtToken(string token, string iss, string aud, byte[] signingKey)
        {
            var jwtHeader = GetJwtHeader(token);
            Console.WriteLine("*** JWT Token header ***\n{0}", jwtHeader.ToString());

            // just get the JWT claims so we can output them to the console
            var jwtPayload = GetJwtPayload(token);
            int nbf = int.Parse(jwtPayload["nbf"].ToString());
            int exp = int.Parse(jwtPayload["exp"].ToString());
            string jwtIss = jwtPayload["iss"].ToString();
            string jwtAud = jwtPayload["aud"].ToString();

            // just so we can show if the token is expired in a sensible way
            int secondsSinceEpoch = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            string time = string.Format("{0} <= {1} < {2}", nbf, secondsSinceEpoch, exp);

            SecurityKey signKey = null;
            string signingKeyMsg = "";
            // self-signed or signed by an OIDC provider
            if (signingKey != null ) {
                signKey = new SymmetricSecurityKey(signingKey);
                signingKeyMsg = "<SymmetricSecurityKey>";
            } else {
                Console.WriteLine("*** creating a JsonWebKey() ***");
                signKey = CreateJsonWebKey(jwtHeader["kid"].ToString());
                signingKeyMsg = jwtHeader["kid"].ToString();
            }
            Console.WriteLine("*** Validating token ***\n- issuer:\t{0} == {1}\n- audience:\t{2} == {3}\n- not expired:\t{4}\n- signing key:\t{5}"
                , iss, jwtIss, aud, jwtAud, time, signingKeyMsg );

            var tokenHandler = new JwtSecurityTokenHandler();
            try {
                tokenHandler.ValidateToken(token, new TokenValidationParameters {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signKey,
                    ValidateIssuer = true, 
                    ValidIssuer = iss,
                    ValidateAudience = true, 
                    ValidAudience = aud,
                    ClockSkew = TimeSpan.Zero // tokens expires on the exact second
                }, out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken;
                Console.WriteLine("*** Valid token ***\n{0}", jwtToken);
                return true;
            } catch( Exception ex ) {
                Console.WriteLine(ex.Message);
                return false;
            }
        }
        private bool LoadB2CMetadata( string wellKnownOidcConfigurationEndpoint )
        {
            Console.WriteLine("*** Getting OIDC metadata ***\n{0}", wellKnownOidcConfigurationEndpoint );
            if (!HttpGet( wellKnownOidcConfigurationEndpoint, out HttpStatusCode statusCode, out string oidcConfig)) { 
                return false;
            }
            var json = JObject.Parse(oidcConfig);
            string jwks_uri = json["jwks_uri"].ToString();
            b2cIssuer = json["issuer"].ToString();

            Console.WriteLine("*** Getting JWKS_URI ***\n{0}", jwks_uri);
            if (!HttpGet(jwks_uri, out statusCode, out string jwksConfig)) {
                return false;
            }
            Console.WriteLine("*** IDP Public Keys ***");
            this.b2cJwksConfig = JObject.Parse(jwksConfig);
            foreach( var key in b2cJwksConfig["keys"] ) {
                Console.WriteLine("kid:\t{0}\nkty:\t{1}", key["kid"], key["kty"] );
            }
            return true;
        }
        private bool HttpGet(string url, out HttpStatusCode statusCode, out string response)
        {
            response = null;
            HttpClient client = new HttpClient();
            HttpResponseMessage res = client.GetAsync(url).Result;
            response = res.Content.ReadAsStringAsync().Result;
            client.Dispose();
            statusCode = res.StatusCode;
            return res.IsSuccessStatusCode;
        }
    } // cls
} // ns
