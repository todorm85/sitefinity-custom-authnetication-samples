using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Telerik.Sitefinity.Data;
using Telerik.Sitefinity.Security;
using Telerik.Sitefinity.Security.Model;
using Telerik.Sitefinity.Services;
using Telerik.Sitefinity.Web;

namespace Telerik.Sitefinity.Samples
{
    // asp managed handler that is used for adding custom external authentication provider to Sitefinity
    // this is for very specific advanced scenarios only
    // if your Identity Provider is using a standard protocol like
    // OpenID Connect or there is one based on OWIN/Katana authentication middleware it is highly recommended that you customize the one provided with Sitefinity instead of writing your own from scratch following this article https://www.progress.com/documentation/sitefinity-cms/for-developers-implement-custom-external-identity-providers
    public class ExternalAuthenticationHandler : IHttpHandler
    {
        private HttpContext context;
        private string returnUrl;
        private string externalUserMappingMethod = "custom";

        public bool IsReusable { get => false; }

        void IHttpHandler.ProcessRequest(HttpContext ctx)
        {
            // redirect to external identity provider where the user will authenticate as per your provider requirements of the protocol used
            if (ctx.Request.Path == "/external.auth/login")
            {
                // returnUrl is the url where the browser would be redirected after the whole external authentication process has finished, typically passed as query string parameter
                var returnUrl = ctx.Request.QueryString.Get("returnUrl");
                var callbackUrl = UrlPath.ResolveAbsoluteUrl("/external.auth/callback") + "?returnUrl=" + HttpUtility.UrlEncode(returnUrl);
                var IPUrl = $"https://www.myidentityprovider.com/login?returnUrl={HttpUtility.UrlEncode(callbackUrl)}"; // + additional parameters as per your identity provider protocol

                // !!! you MUST add addtional security parameters to check when the browser redirects back to the callback path. This is implementation specific.

                // redirect to the identity provider
                ctx.Response.StatusCode = 302;
                ctx.Response.AddHeader("Location", IPUrl);
            }

            // after login at an external identity provider this is the action where the identity provider should redirect back to your web application with the authentication result as per the protocol used
            if (ctx.Request.Path == "/external.auth/callback")
            {
                this.context = ctx;
                this.returnUrl = ctx.Request.QueryString.Get("returnUrl");

                // Validate authentication was successful as per your provider protocol

                // For mapping external users to local user accounts external identifier must be received by the external identity provider
                // The external identifier must be unique per user for the specific external provider
                // For demo purposes a random id is generated here
                var externalId = "dummyExternalID_" + Guid.NewGuid().ToString();

                // you can also optionally retrieve other user information from the external provider like email, contact, age, location etc.

                // finally you have two options:

                if (this.externalUserMappingMethod == "custom")
                {
                    // Option 1
                    //  Custom handling of user creation and mapping to the authenticated external identity. Keep in mind that with this option features like 'Claims to roles mappings' 'Map users via email' and 'Claims to fields mappings' will not work and you have to implement them as well.
                    this.CustomizedExternalUserMapping(externalId);
                }
                else if (this.externalUserMappingMethod == "default")
                {
                    // Option 2
                    // Sitefinity to handle the local user account mapping and automatic creation.
                    // IMPORTANT! You also MUST register an external provider configuration in Sitefinity as described in section "Register custom external identity provider": https://www.progress.com/documentation/sitefinity-cms/for-developers-implement-custom-external-identity-providers#register-custom-external-identity-provider. You do not need to register it as OpenID Connect type, you can use a generic AuthenticationProviderElement type. Only register the configuration as described in the section of the page Register custom external identity provider.
                    this.SitefinityHandledExternalUserMapping(externalId);
                }
            }
        }

        private void SitefinityHandledExternalUserMapping(string externalId)
        {
            ClaimsIdentity identity = new ClaimsIdentity("sitefinity.external");
            identity.AddClaim(new Claim("sub", externalId));

            var props = new AuthenticationProperties() { RedirectUri = returnUrl };

            props.Dictionary.Add("externalProviderName", "MyCustomIdentityProvider"); // the name must match the one from the configuration that you registered previously in Sitefinity

            // optionally if claims are provided
            ////identity.AddClaim(new Claim(SitefinityClaimTypes.ExternalUserEmail, email));
            ////identity.AddClaim(new Claim("ClaimsMapping:SitefinityProfile.FirstName", externalId));
            ////identity.AddClaim(new Claim("ClaimsMapping:SitefinityProfile.LastName", externalId));

            // optionally you can also add profile picture claim - SitefinityClaimTypes.ExternalUserPictureUrl
            // to map any other information from the remote server about the user to the automatically created user profile use
            // the following KB: https://knowledgebase.progress.com/articles/Article/Authentication-What-types-of-claims-can-be-mapped-to-profile-fields-when-using-a-custom-external-identity-provider

            this.context.Request.GetOwinContext().Authentication.SignIn(props, identity);
        }

        private void CustomizedExternalUserMapping(string externalId)
        {
            if (UserManager.GetManager().GetUsers().Where(u => u.ExternalId == externalId).FirstOrDefault() == null)
            {
                SystemManager.RunWithElevatedPrivilege(p =>
                {
                    this.CreateSfUser(dataProviderName: string.Empty,
                        externalId: externalId,
                        initialRoles: new List<string>() { "Administrators", "BackendUsers" });
                });
            }

            bool persistedCookie = false; // you can further implement logic whether to issue persistent or session cookies.
            this.LoginUser(externalId, persistedCookie);
        }

        private void LoginUser(string username, bool persistCookie)
        {
            UserLoggingReason result = SecurityManager.AuthenticateUser(
                            string.Empty,
                            username,
                            persistCookie,
                            out _);

            if (result != UserLoggingReason.Success)
            {
                // choose where to redirect to if an error occurrs. For demo purpose browser redirects back to the originally provided return url with error query param
                context.Response.StatusCode = 302;
                context.Response.AddHeader("Location", returnUrl + "?error=" + HttpUtility.UrlEncode(result.ToString()));
            }
            else
            {
                context.Response.StatusCode = 302;
                context.Response.AddHeader("Location", returnUrl);
            }
        }

        private void CreateSfUser(string dataProviderName, List<string> initialRoles, string externalId)
        {
            if (string.IsNullOrWhiteSpace(externalId))
            {
                throw new ArgumentNullException("externalId");
            }

            var transaction = "ExternalLoginCreateUserTransaction" + Guid.NewGuid().ToString();
            var userManager = UserManager.GetManager(dataProviderName, transaction);
            var profileManager = UserProfileManager.GetManager(string.Empty, transaction);

            // you need to uniquely identify the locally created user account that is linked to the external identity
            // in the sample the identity provider name which is unique for all teh users of this provider in Sitefinity
            // and the externalId returned by the remote server which is unique for the remote account are used
            var dbUser = userManager.GetUsers().Where(u => u.ExternalId == externalId &&
                u.ExternalProviderName == "CustomIdentityProvider")
                .FirstOrDefault();
            dbUser = userManager.CreateUser(null);
            dbUser.SetUserName(externalId); // username for accounts mapped to external users is only used in code to login the user programatically after successful login on the external provider hence we set it to the unique identifier value
            dbUser.IsBackendUser = initialRoles.Contains("BackendUsers");
            dbUser.ExternalId = externalId;
            dbUser.ExternalProviderName = "CustomIdentityProvider"; // you can use the one from advanced settings it is used to separate external accounts from different providers

            var roleProviders = RoleManager.StaticProvidersCollection;
            foreach (var roleToAdd in initialRoles.Distinct())
            {
                foreach (var roleProvider in roleProviders)
                {
                    var roleManager = RoleManager.GetManager(roleProvider.Name, transaction);
                    var role = roleManager.GetRoles().Where(r => r.Name == roleToAdd).FirstOrDefault();
                    if (role != null)
                    {
                        roleManager.AddUserToRole(dbUser, role);
                        break;
                    }
                }
            }

            var profile = profileManager.CreateProfile(dbUser, "Telerik.Sitefinity.Security.Model.SitefinityProfile") as SitefinityProfile;
            // set other profile fields here
            ////profile.FirstName = Guid.NewGuid().ToString();
            ////profile.Nickname = Guid.NewGuid().ToString().Split('-').Last();

            TransactionManager.FlushTransaction(transaction);
            profileManager.RecompileItemUrls<SitefinityProfile>(profile);
            TransactionManager.CommitTransaction(transaction);
        }
    }
}
