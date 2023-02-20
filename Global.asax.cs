using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using Telerik.Sitefinity.Abstractions;

namespace Telerik.Sitefinity.Samples
{
    public class Global : System.Web.HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            Bootstrapper.Bootstrapped += Bootstrapper_Bootstrapped;
        }

        // classic MVC mode as per https://www.progress.com/documentation/sitefinity-cms/for-developers-classic-mvc-mode
        private void Bootstrapper_Bootstrapped(object sender, EventArgs e)
        {
            System.Web.Mvc.RouteCollectionExtensions.MapRoute(System.Web.Routing.RouteTable.Routes,
                 "Classic",
                 "samples/{controller}/{action}",
                 new { controller = "ExternalAuthentication", action = "ExternalProviderLogin" }
             );
        }
    }
}