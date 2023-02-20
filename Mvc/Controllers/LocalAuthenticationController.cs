using System.Web.Mvc;
using Telerik.Sitefinity.Frontend.Security;
using Telerik.Sitefinity.Mvc;
using Telerik.Sitefinity.Security;
using Telerik.Sitefinity.Samples.Mvc.Models;

namespace Telerik.Sitefinity.Samples.Mvc.Controllers
{
    /// <summary>
    /// This Sitefinity login widget completely bypasses the password-based authentication mechanism for Sitefinity`s local user accounts.
    /// </summary>
    [ControllerToolboxItem(Name = "CustomLogin", Title = "Custom Login", SectionName = "MvcWidgets")]
    public class LocalAuthenticationController : Controller
    {
        public ActionResult Index()
        {
            return this.View();
        }

        [HttpPost]
        public ActionResult Index(LocalAuthenticationViewModel model)
        {
            // model validation here
            if (!AntiCsrfHelpers.IsValidCsrfToken(this.Request?.Form))
                return new EmptyResult();

            // YOUR CUSTOM AUTHNETICATION LOGIC HERE!
            // you can choose to process some input from the form (like hardware dongle code) and/or validate with external system etc.

            // finally force login the user bypassing Sitefinity`s password based authentication like this
            return this.LoginUser(model.Username, model.RememberMe);
        }

        private ActionResult LoginUser(string username, bool persistCookie)
        {
            UserLoggingReason result = SecurityManager.AuthenticateUser(
                            string.Empty,
                            username,
                            persistCookie,
                            out _);

            if (result != UserLoggingReason.Success)
            {
                this.ViewBag.error = "Error";
                return this.View();
            }
            else
            {
                this.ViewBag.error = null;
                return this.RedirectToAction("Index");
            }
        }
    }
}