using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Specialized;
using System.Globalization;
using System.Net.Http.Headers;

namespace HMACAuth
{
    [AttributeUsage(AttributeTargets.Class|AttributeTargets.Method,AllowMultiple=false,Inherited=true)]
    public class HMACAuthAttribute : AuthorizeAttribute, IDisposable
    {
        Encoding Encoding { get; set; }
        SecurityProvider SecurityProvider { get; set; }
        IEnumerable<APIUser> users;
        IEnumerable<APIUser> Users { get { return users; } }
        //Context db;
        Role MinimumRole { get; set; }
        string responseContent = "";
        TimeSpan maxDelay = new TimeSpan(0, 15, 0);
        TimeSpan MaxQuerytimeoutLength { get; set; }
        CultureInfo EndUserDateFormat { get; set; }
        Encoding KeyFormatEncoding { get; set; }
        IEnumerable<string> ParametersToIgnore { get; set; }

        public HMACAuthAttribute(IEnumerable<APIUser> users)
        {
            this.users = users;
            this.MinimumRole = Role.User;
            this.EndUserDateFormat = new CultureInfo("en-US");
            this.KeyFormatEncoding = new UTF8Encoding();
            this.ParametersToIgnore = new List<string>();
            this.SecurityProvider = SecurityProvider.HMACSHA1;
        }

        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            HttpRequestHeaders headers = actionContext.Request.Headers;
            AuthorizationComponents result = default(AuthorizationComponents);

            try
            {
                result = TakeHeaderData(headers);
            }
            catch (NoKeyProvidedException ex)
            {
                responseContent = "No key was provided with the request";
                HandleUnauthorizedRequest(actionContext);
            }
            catch (NoDateProvidedException ex)
            {
                responseContent = "No date was provided with the request";
                HandleUnauthorizedRequest(actionContext);
            }
            catch (NoHashProvidedEception ex)
            {
                responseContent = "No hash was provided with the request";
                HandleUnauthorizedRequest(actionContext);
            }
            catch (InvalidHeaderException ex)
            {
                responseContent = "There was a problem with the sent " + ex.Message;
                HandleUnauthorizedRequest(actionContext);
            }
            catch (FormatException ex)
            {
                responseContent = "There was an error parsing the supplied date";
                HandleUnauthorizedRequest(actionContext);
            }

            try
            {
                bool success = CheckForNotStaleData(result.TimeRequestExecuted);
                if (!success)
                {
                    responseContent = "The request was sent with a stale sent time";
                    HandleUnauthorizedRequest(actionContext);
                }
            }
            catch (InvalidSentTimeException ex)
            {
                responseContent = ex.Message;
                HandleUnauthorizedRequest(actionContext);
            }

            APIUser apiUser = null;
            try
            {
                apiUser = users.GetAPIUser(result.PublicKey);
            }
            catch (NoUsersFoundException ex)
            {
                responseContent = "No users in the database match the given public key";
                HandleUnauthorizedRequest(actionContext);
            }
            catch (MultipleUsersException ex)
            {
                responseContent = "There are multiple acounts which match that public key";
                HandleUnauthorizedRequest(actionContext);
            }

            if (apiUser != null)
            {
                var privateKey = apiUser.PrivateKey;
                if ((int)apiUser.PrivilegeLevel < (int)MinimumRole)
                {
                    responseContent = "You do not have the permission required to execute this request";
                    HandleUnauthorizedRequest(actionContext);
                }
                var parsedQS = HttpUtility.ParseQueryString(actionContext.Request.RequestUri.AbsoluteUri);
                var serverCalculatedHash = CalculateHash(parsedQS, result, apiUser);
                var convertedHash = Convert.ToBase64String(serverCalculatedHash);
                if (convertedHash != result.DataHash)
                {
                    responseContent = "The specified hash does not match the computed hash";
                    HandleUnauthorizedRequest(actionContext);
                }
            }
        }

        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            var response = actionContext.Request.CreateResponse(HttpStatusCode.Forbidden);
            if (!String.IsNullOrWhiteSpace(responseContent))
            {
                response.ReasonPhrase = responseContent;
            }
            actionContext.Response = response;
        }

        private byte[] CalculateHash(NameValueCollection QueryString, AuthorizationComponents components, APIUser user)
        {
            var privateKeyBytes = KeyFormatEncoding.GetBytes(user.PrivateKey);
            var messageBytes = KeyFormatEncoding.GetBytes(components.DataHash);
            KeyedHashAlgorithm provider = HashProviderFactory.GetInstance(this.SecurityProvider);
            provider.Key = privateKeyBytes;
            string fullString = "";
            foreach (string key in QueryString.Keys)
            {
                foreach (var value in QueryString.GetValues(key))
                {
                    if (ParametersToIgnore.Contains(value))
                        continue;
                    fullString += value;
                }
            }
            fullString += components.TimeRequestExecuted;
            return provider.ComputeHash(KeyFormatEncoding.GetBytes(fullString));
        }

        public void Dispose()
        {
        }

        private AuthorizationComponents TakeHeaderData(HttpRequestHeaders headers)
        {
            string key = "", hash = "", dateTimeSent = "";
            if (headers.Contains("Key"))
                key = headers.GetValues("key").First();
            else
            {
                throw new NoKeyProvidedException();
            }
            if (headers.Contains("Hash"))
                hash = headers.GetValues("hash").First();
            else
            {
                throw new NoHashProvidedEception();
            }
            if (headers.Contains("DateSent"))
                dateTimeSent = headers.GetValues("DateSent").First();
            else
            {
                throw new NoDateProvidedException();
            }

            if (String.IsNullOrWhiteSpace(key))
            {
                throw new InvalidHeaderException("key");
            }
            if(String.IsNullOrWhiteSpace(hash))
            {
                throw new InvalidHeaderException("hash");
            }
            if(String.IsNullOrWhiteSpace(dateTimeSent))
            {
                throw new InvalidHeaderException("date");
            }
            DateTime sent = DateTime.Parse(dateTimeSent, this.EndUserDateFormat, DateTimeStyles.AssumeUniversal);
            return new AuthorizationComponents { PublicKey = key, DataHash = hash, TimeRequestExecuted = sent };
        }

        private bool CheckForNotStaleData(DateTime sent)
        {
            TimeSpan sentAgo = DateTime.UtcNow - sent;
            if (sentAgo < new TimeSpan(0))
            {
                throw new InvalidSentTimeException("The request was sent after the time now");
            }
            if (sentAgo > MaxQuerytimeoutLength)
            {
                return false;
            }
            return true;
        }
    }
}