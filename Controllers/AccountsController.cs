namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Accounts;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("[controller]")]
public class AccountsController : BaseController
{
    private readonly IAccountService _accountService;

    public AccountsController(IAccountService accountService)
    {
        _accountService = accountService;
    }

    /*
     Authenticate to get a JWT token and a refresh token
     POST /accounts/authenticate - public route that accepts POST requests containing an
     email and password in the body. On success a JWT access token is returned with basic
     account details, and an HTTP Only cookie containing a refresh token.
    */
    [AllowAnonymous]
    [HttpPost("authenticate")]
    public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model)
    {
        var response = _accountService.Authenticate(model, ipAddress());
        setTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    /*
     Use a refresh token to get a new JWT token
     POST /accounts/refresh-token - public route that accepts POST requests containing a
     cookie with a refresh token. On success a new JWT access token is returned with basic
     account details, and an HTTP Only cookie containing a new refresh token.
    */
    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public ActionResult<AuthenticateResponse> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _accountService.RefreshToken(refreshToken, ipAddress());
        setTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    /*
     Revoke a refresh token
     POST /accounts/revoke-token - secure route that accepts POST requests containing a
     refresh token either in the request body or in a cookie, if both are present priority is
     given to the request body. On success the token is revoked and can no longer be used
     to generate new JWT access tokens.
    */
    [HttpPost("revoke-token")]
    public IActionResult RevokeToken(RevokeTokenRequest model)
    {
        // accept token from request body or cookie
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required" });

        // users can revoke their own tokens and admins can revoke any tokens
        if (!Account.OwnsToken(token) && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        _accountService.RevokeToken(token, ipAddress());
        return Ok(new { message = "Token revoked" });
    }

    /* 
     Register a new account
     POST /accounts/register - public route that accepts POST requests containing
     account registration details. On success the account is registered and a verification
     email is sent to the email address of the account, accounts must be verified before they
     can authenticate.
    */
    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest model)
    {
        _accountService.Register(model, Request.Headers["origin"]);
        return Ok(new { message = "Registration successful, please check your email for verification instructions" });
    }

    /*
     Verify an account
     POST /accounts/verify-email - public route that accepts POST requests containing an
     account verification token. On success the account is verified and can now login.
    */
    [AllowAnonymous]
    [HttpPost("verify-email")]
    public IActionResult VerifyEmail(VerifyEmailRequest model)
    {
        _accountService.VerifyEmail(model.Token);
        return Ok(new { message = "Verification successful, you can now login" });
    }

    /* 
     Reset the password of an account step one
     POST /accounts/forgot-password - public route that accepts POST requests containing
     an account email address. On success a password reset email is sent to the email
     address of the account. The email contains a single use reset token that is valid for one
     day.
    */
    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public IActionResult ForgotPassword(ForgotPasswordRequest model)
    {
        _accountService.ForgotPassword(model, Request.Headers["origin"]);
        return Ok(new { message = "Please check your email for password reset instructions" });
    }

    /*
     Reset the password of an account step two
     POST /accounts/validate-reset-token - public route that accepts POST requests
     containing a password reset token. A message is returned to indicate if the token is
     valid or not.
    */
    [AllowAnonymous]
    [HttpPost("validate-reset-token")]
    public IActionResult ValidateResetToken(ValidateResetTokenRequest model)
    {
        _accountService.ValidateResetToken(model);
        return Ok(new { message = "Token is valid" });
    }

    /*
     Reset the password of an account step three
     POST /accounts/reset-password - public route that accepts POST requests containing
     a reset token, password and confirm password. On success the account password is
     reset.
    */
    [AllowAnonymous]
    [HttpPost("reset-password")]
    public IActionResult ResetPassword(ResetPasswordRequest model)
    {
        _accountService.ResetPassword(model);
        return Ok(new { message = "Password reset successful, you can now login" });
    }

    /*
     Get a list of all accounts
     GET /accounts - secure route restricted to the Admin role that accepts GET requests
     and returns a list of all the accounts in the application.
    */
    [Authorize(Role.Admin)]
    [HttpGet]
    public ActionResult<IEnumerable<AccountResponse>> GetAll()
    {
        var accounts = _accountService.GetAll();
        return Ok(accounts);
    }

    /*
     Get account details
     GET /accounts/{id} - secure route that accepts GET requests and returns the details of
     the account with the specified id. The Admin role can access any account, the User role
     can only access their own account.
    */
    [HttpGet("{id:int}")]
    public ActionResult<AccountResponse> GetById(int id)
    {
        // users can get their own account and admins can get any account
        if (id != Account.Id && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        var account = _accountService.GetById(id);
        return Ok(account);
    }

    /*
     Create an account
     POST /accounts - secure route restricted to the Admin role that accepts POST requests
     containing new account details. On success the account is created and automatically
     verified.
    */
    [Authorize(Role.Admin)]
    [HttpPost]
    public ActionResult<AccountResponse> Create(CreateRequest model)
    {
        var account = _accountService.Create(model);
        return Ok(account);
    }

    /*
     Update an account
     PUT /accounts/{id} - secure route that accepts PUT requests to update the details of
     the account with the specified id. The Admin role can update any account including its
     role, the User role can only update there own account details except for role.
    */
    [HttpPut("{id:int}")]
    public ActionResult<AccountResponse> Update(int id, UpdateRequest model)
    {
        // users can update their own account and admins can update any account
        if (id != Account.Id && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        // only admins can update role
        if (Account.Role != Role.Admin)
            model.Role = null;

        var account = _accountService.Update(id, model);
        return Ok(account);
    }

    /*
     Delete an account
     DELETE /accounts/{id} - secure route that accepts DELETE requests to delete the
     account with the specified id. The Admin role can delete any account, the User role can
     only delete their own account.
    */
    [HttpDelete("{id:int}")]
    public IActionResult Delete(int id)
    {
        // users can delete their own account and admins can delete any account
        if (id != Account.Id && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        _accountService.Delete(id);
        return Ok(new { message = "Account deleted successfully" });
    }

    private void setTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string ipAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}