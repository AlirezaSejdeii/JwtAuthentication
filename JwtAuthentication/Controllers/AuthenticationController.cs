using JwtAuthentication.Models.ViewModels;
using JwtAuthentication.Models.ViewModels.Atuh;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Utilites;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly JwtConfig _jwtConfig;

        private readonly string SendedConfirmKey = "SendedConfirmKey";

        public AuthenticationController(UserManager<IdentityUser> userManager, IOptionsMonitor<JwtConfig> optionsMonitor, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _signInManager = signInManager;
        }


        /// <summary>
        /// Action For Get Access Token
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("/Login")]
        public async Task<ActionResult<AuthResult>> LoginAsync([FromBody] UserLoginRequest user)
        {
            if (ModelState.IsValid)
            {
                // check if the user with the same email exist
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>(){
                                        "User Is Invalid"
                                    }
                    });
                }

                // Now we need to check if the user has inputed the right password
                var signIn = await _signInManager.PasswordSignInAsync(existingUser, user.Password, false, true);

                //check use allow to sign in
                if (signIn.IsNotAllowed is true)
                {
                    //if send one or more confirm email, dose not send again
                    var confirmSended = HttpContext.Session.GetInt32(SendedConfirmKey);
                    if (confirmSended.HasValue is false)
                    {
                        await SendConfirmationEmail(existingUser);
                    }
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "Email is not valid" }
                    });
                }
                if (signIn.IsLockedOut is true)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "Your Account was lockedout for few time" }
                    });
                }
                if (signIn.Succeeded)
                {
                    var jwtToken = GenerateJwtToken(existingUser);

                    return Ok(new AuthResult()
                    {
                        Result = true,
                        Token = jwtToken
                    });
                }
                else
                {
                    // We dont want to give to much information on why the request has failed for security reasons
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>(){
                                         "Invalid Login"
                                    }
                    });
                }
            }

            return BadRequest(new AuthResult()
            {
                Result = false,
                Messages = new List<string>(){
                      "Inputs not valid"
                    }
            });
        }


        /// <summary>
        /// Action For Store User Data And Get Confirmation Email
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("/Register")]
        public async Task<ActionResult<AuthResult>> RegisterAsync([FromBody] UserRegistrationRequestDto user)
        {
            // Check if the incoming request is valid
            if (ModelState.IsValid)
            {
                // check i the user with the same email exist
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser != null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "User was exsist" }
                    });
                }

                var newUser = new IdentityUser() { Email = user.Email, UserName = user.Name };
                var isCreated = await _userManager.CreateAsync(newUser, user.Password);
                if (isCreated.Succeeded)
                {
                    //var jwtToken = GenerateJwtToken(newUser);
                    await SendConfirmationEmail(newUser);
                    return Ok(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "For activation your email click sended link in your email" }
                    });
                }

                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Messages = isCreated.Errors.Select(x => x.Description).ToList()
                });

            }

            return BadRequest(new AuthResult()
            {
                Result = false,
                Messages = new List<string>() { "Inputs not valid" }
            });
        }
        /// <summary>
        /// For Recovery Password:
        /// First: Send User Email From This Action
        /// Second: You Get An Email, Open It, Click The Link,
        /// Impelemnt A View For That Link. Get Email Addresss And Token
        /// Thered: Send Token,Email,NewPassword To RecoveryPasswordConfirm Action 
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpGet("RecoveryPassword")]
        public async Task<ActionResult<AuthResult>> RecoveryPasswordAsync(string email)
        {
            if (ModelState.IsValid)
            {
                var exsistUser = await _userManager.FindByEmailAsync(email);
                if (exsistUser is null)
                {
                    return Ok(new AuthResult() { Messages = new List<string>() { "User not exsist" } });

                }
                string tokenGenreated = await _userManager.GeneratePasswordResetTokenAsync(exsistUser);

                string link = Url.Action("RecoveryPassword", "Authentication", new { token = tokenGenreated, email = email,newpassword="78452211212" });
                string body = $"Hello frend " +
                        $"</br>" +
                        $" For validating Email click below link" +
                        $" </br> </br>" +
                        $" <a href={$"{link}"}+> Recovery password </a>";

                SendEmail.send("Recovey Password", body, email, exsistUser.UserName);


                return Ok(new AuthResult()
                {
                    Messages = new List<string> { "Sended email for validate email" }
                }); ;
            }
            return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });
        }
        /// <summary>
        /// This Action For Recovery Password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("RecoveryPassword")]
        public async Task<ActionResult<AuthResult>> RecoveryPasswordConfirmAsync([FromBody] RecoveryPasswordConfirmViewModel model)
        {
            if (ModelState.IsValid)
            {
                model.Token = System.Net.WebUtility.UrlDecode(model.Token);

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user is null)
                {
                    return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });
                }
                var changePassword = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

                if (changePassword.Succeeded)
                {
                    return Ok(new AuthResult() { Messages = new List<string>() { "Password Success changed" } });
                }
                else
                {
                    return BadRequest(new AuthResult() { Messages = changePassword.Errors.Select(x => x.Description).ToList() });
                }
            }
            return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });
        }
        /// <summary>
        /// This Action For Active Confirmation. User After Confirm Email Can Get Token.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /// <summary>
        /// This Action For Active Confirmation. User After Confirm Email Can Get Token.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpGet("ConfirmEmail")]
        public async Task<ActionResult<AuthResult>> ConfirmEmailAsync([FromQuery] EmailConfirmViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.email);
                if (user == null)
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "Link not valid" }
                    });
                var result = await _userManager.ConfirmEmailAsync(user, model.token);
                return Ok(new AuthResult()
                {
                    Result = false,
                    Messages = new List<string>() { "Please login" }
                }); ;
            }
            return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });

        }

        [HttpPost("ResetPassword")]
        public async Task<ActionResult<AuthResult>> ResetPasswordAsync([FromBody] RestPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (User.Identity.IsAuthenticated is false)
                {
                    return BadRequest(new AuthResult()
                    {
                        Messages = new List<string>() { "You're not login" }
                    });
                }
                var username = User.Claims.FirstOrDefault(a => a.Type == ClaimTypes.Email).Value;
                var user = await _userManager.FindByEmailAsync(username);

                var changePassword = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (changePassword.Succeeded)
                {
                    return Ok(new AuthResult() { Messages = new List<string>() { "Your passwod successfuly chenged" } });
                }
                else
                {
                    return BadRequest(new AuthResult() { Messages = changePassword.Errors.Select(a => a.Description).ToList() });
                }
                //_userManager.GetUserAsync()
            }
            return BadRequest(new AuthResult()
            {
                Messages = new List<string>() { "Inputs not valid" }
            });
        }

        private async Task SendConfirmationEmail(IdentityUser user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action("ConfirmEmail", "Authentication", new { token, email = user.Email }, Request.Scheme);
            var body = $"hello frend " +
                $"</br>" +
                $" For validate your email click below link" +
                $" </br> </br>" +
                $" <a href={$"{confirmationLink}"}> validate email </a>";
            SendEmail.send("validate email", body, user.Email, user.UserName);
            HttpContext.Session.SetInt32(SendedConfirmKey, 1);

        }
        private string GenerateJwtToken(IdentityUser user)
        {
            // Now its ime to define the jwt token which will be responsible of creating our tokens
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            // We get our secret from the appsettings
            //for encript token genrated
            var Secretkey = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
            var SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Secretkey), SecurityAlgorithms.HmacSha512Signature);

            //for encript values in token
            var EncryptionKey = Encoding.ASCII.GetBytes(_jwtConfig.EncryptionKey);
            var EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(EncryptionKey), SecurityAlgorithms.Aes128KW,SecurityAlgorithms.Aes128CbcHmacSha256);

            // we define our token descriptor
            // We need to utilise claims which are properties in our token which gives information about the token
            // which belong to the specific user who it belongs to
            // so it could contain their id, name, email the good part is that these information
            // are generated by our server and identity framework which is valid and trusted
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
                // the JTI is used for our refresh token 
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
                // the life span of the token needs to be shorter and utilise refresh token to keep the user signedin
                // but since this is a demo app we can extend it to fit our current need
                Expires = DateTime.UtcNow.AddHours(6),
                // here we are adding the encryption alogorithim information which will be used to decrypt our token
                SigningCredentials = SigningCredentials,
                //add jwt excriptin
                EncryptingCredentials = EncryptingCredentials
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }

    }
}
