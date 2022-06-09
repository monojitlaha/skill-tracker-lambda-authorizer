using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]


namespace SkillTrackerLambdaAuthorizer
{
    public class Function
    {
        public Function()
        {

        }

        /// <summary>
        /// A Lambda function to respond to HTTP Get methods from API Gateway
        /// </summary>
        /// <param name="request"></param>
        /// <returns>The list of blogs</returns>
        public APIGatewayCustomAuthorizerResponse Get(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
        {
            context.Logger.LogLine("Get Request\n");
            
            context.Logger.LogLine($"Token: {request.AuthorizationToken}\n");
            var secret = "Skilltrackerprivatekey";
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secret))
            };

            return CreateAuthorizerResponse(request, context, tokenValidationParameters);
        }

        private APIGatewayCustomAuthorizerResponse CreateAuthorizerResponse(APIGatewayCustomAuthorizerRequest request, ILambdaContext context, TokenValidationParameters tokenValidationParameters)
        {
            SecurityToken validatedToken;

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            bool authorized = false;

            if (!string.IsNullOrWhiteSpace(request.AuthorizationToken))
            {
                try
                {
                    var user = handler.ValidateToken(request.AuthorizationToken, tokenValidationParameters, out validatedToken);

                    //optional: custom claim validation
                    //var claim = user.Claims.FirstOrDefault(c => c.Type == "ClaimTypeName");
                    //if (claim != null)
                    // authorized = claim.Value == "ExpectedValue";

                    authorized = true;
                }
                catch (Exception e)
                {
                    context.Logger.LogLine($"Exception thrown while validationg token-> {e.ToString()}");
                    throw;
                }
            }

            APIGatewayCustomAuthorizerPolicy policy = new APIGatewayCustomAuthorizerPolicy()
            {
                Version = "2012-10-17", //constant value required by AWS, don't change
                Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>()
            };

            policy.Statement.Add(new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
            {
                Action = new HashSet<string>(new string[] { "execute-api:Invoke" }),
                Effect = authorized ? "Allow" : "Deny",
                Resource = new HashSet<string>(new string[] { request.MethodArn })
            });

            context.Logger.LogLine($"Policy created, isAuthorized: {authorized}\n");

            var contextOutput = new APIGatewayCustomAuthorizerContextOutput();
            contextOutput["User"] = "User";
            contextOutput["Path"] = request.MethodArn;

            return new APIGatewayCustomAuthorizerResponse
            {
                PrincipalID = "User",
                Context = contextOutput,
                PolicyDocument = policy
            };
        }
    }
}
