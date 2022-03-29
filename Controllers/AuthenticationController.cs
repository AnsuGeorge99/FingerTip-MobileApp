using FingerTip_MobileApp.Authentication;
using FingerTip_MobileApp.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FingerTip_MobileApp.Controllers
{
    [Authorize(Roles = UserRoles.admin)]
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._configuration = configuration;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            var userExist = await _userManager.FindByNameAsync(register.username);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User already exists" });
            }
                ApplicationUser user = new ApplicationUser()
                {
                    Email = register.email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = register.username
                };
                var result = await _userManager.CreateAsync(user, register.password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User registration failed, please try again" });
            }
            return Ok(new Response { status = "Success", message = "User registration is successfully completed" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var user = await _userManager.FindByNameAsync(login.username);
            if (user != null && await _userManager.CheckPasswordAsync(user, login.password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach(var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var authSignInKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                var token = new JwtSecurityToken
                    (
                    issuer : _configuration["JWT:ValidIssuer"],
                    audience : _configuration["JWT:ValidAudience"],
                    expires : DateTime.Now.AddHours(3),
                    claims : authClaims,
                    signingCredentials : new SigningCredentials(authSignInKey, SecurityAlgorithms.HmacSha256)
                    );
                return Ok(new
                {
                    token=new JwtSecurityTokenHandler().WriteToken(token)
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("RegisterAdmin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] Register register)
        {
            var userExist = await _userManager.FindByNameAsync(register.username);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User already exists" });
            }
            ApplicationUser user = new ApplicationUser()
            {
                Email = register.email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = register.username
            };
            var result = await _userManager.CreateAsync(user, register.password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User registration failed, please try again" });
            }
            if (!await _roleManager.RoleExistsAsync(UserRoles.admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.user))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.user));
            if (await _roleManager.RoleExistsAsync(UserRoles.admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.admin);
            }
            return Ok(new Response { status = "Success", message = "User registration is successfully completed" });
        }
    }
   
}
