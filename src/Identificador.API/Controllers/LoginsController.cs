﻿using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Identificador.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Identificador.API.Controllers
{
    [Route("api/[controller]")]
    public class LoginsController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly SigningConfigurations _signInConfigurations;
        private readonly TokenConfigurations _tokenConfigurations;

        public LoginsController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
            SigningConfigurations signingConfigurations, TokenConfigurations tokenConfigurationses,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _signInConfigurations = signingConfigurations;
            _tokenConfigurations = tokenConfigurationses;
            _roleManager = roleManager;
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("user")]
        public async Task<OkResult> Register([FromBody]User user)
        {
            var userApplication = new ApplicationUser {UserName = user.UserID, Email = user.Email};
            var result = await _userManager.CreateAsync(userApplication, user.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(userApplication, Roles.ROLE_USER);
                return Ok();
            }
            throw new Exception("Can't create the user");
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("adminUser")]
        public async Task<OkResult> RegisterAdmin([FromBody]User user)
        {
            if (user != null && !String.IsNullOrWhiteSpace(user.UserID))
            {
                var userIdentity = _userManager
                    .FindByNameAsync(user.UserID).Result;
                if (userIdentity != null)
                {
                    var loginResult = _signInManager
                        .CheckPasswordSignInAsync(userIdentity, user.Password, false)
                        .Result;
                    if (loginResult.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(userIdentity, Roles.ROLE_ADMIN);
                        return Ok();
                    }
                }
            }
            throw new Exception("Can't create the user");
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<object> LogIn([FromBody]User user)
        {
            bool validCredentials = false;
            var userIdentity = new ApplicationUser();
            if (user != null && !string.IsNullOrWhiteSpace(user.UserID))
            {
                userIdentity = _userManager
                    .FindByNameAsync(user.UserID).Result;
                if (userIdentity != null)
                {
                    var loginResult = _signInManager
                        .CheckPasswordSignInAsync(userIdentity, user.Password, false)
                        .Result;
                    if (loginResult.Succeeded)
                    {
                        validCredentials = _userManager.IsInRoleAsync(
                            userIdentity, Roles.ROLE_USER).Result;
                    }
                }
            }

            if (validCredentials)
            {
                ClaimsIdentity identity = new ClaimsIdentity(
                    new GenericIdentity(user.UserID, "Login"),
                    new[] {
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                        new Claim(JwtRegisteredClaimNames.UniqueName, user.UserID)
                    }
                );
                var roles = await _userManager.GetRolesAsync(userIdentity);
                foreach (var role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }

                DateTime createDate = DateTime.Now;
                DateTime expirationDate = createDate +
                    TimeSpan.FromSeconds(_tokenConfigurations.Seconds);

                var handler = new JwtSecurityTokenHandler();
                var securityToken = handler.CreateToken(new SecurityTokenDescriptor
                {
                    Issuer = _tokenConfigurations.Issuer,
                    Audience = _tokenConfigurations.Audience,
                    SigningCredentials = _signInConfigurations.SigningCredentials,
                    Subject = identity,
                    NotBefore = createDate,
                    Expires = expirationDate
                });
                var token = handler.WriteToken(securityToken);

                return new
                {
                    authenticated = true,
                    created = createDate.ToString("yyyy-MM-dd HH:mm:ss"),
                    expiration = expirationDate.ToString("yyyy-MM-dd HH:mm:ss"),
                    accessToken = token,
                    message = "OK"
                };
            }
            else
            {
                return new
                {
                    authenticated = false,
                    message = "Not authenticating"
                };
            }
        }
    }
}