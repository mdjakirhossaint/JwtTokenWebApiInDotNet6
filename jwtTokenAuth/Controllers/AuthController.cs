using jwtTokenAuth.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jwtTokenAuth.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly IConfiguration _configuration;
		public AuthController(IConfiguration configuration, UserManager<IdentityUser> userManager)
		{
			_configuration = configuration;
			_userManager = userManager;
		}
		[HttpPost]
		public async Task<IActionResult> RegisterUser([FromBody] RegisterViewModel model)
		{
			var ExistUser =await  _userManager.FindByNameAsync(model.Username);
			if (ExistUser!=null)
			{
				return StatusCode(StatusCodes.Status500InternalServerError,new Response {Status="Error",Message="This username already exist in our server" });
			}
			IdentityUser user = new IdentityUser()
			{
				NormalizedUserName = model.Username,
				UserName = model.Username,
			};

			var result = await _userManager.CreateAsync(user,model.Password);

			if (!result.Succeeded) 
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "The user not save successfully" });
			}
			return Ok(new Response { Status="Success",Message="User has successfully inserted !"});
		}
		[HttpPost]
		[Route("UserLogin")]
		public async Task<IActionResult> Login([FromBody] LoginViewModel model)
		{
			var user = await _userManager.FindByNameAsync(model.Username);
			if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
			{
				var userRoles = await _userManager.GetRolesAsync(user);
				var authClaims = new List<Claim>
				{
					new Claim(ClaimTypes.Name,user.UserName),
					new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
				};
				foreach (var userRole in userRoles)
				{
					authClaims.Add(new Claim(ClaimTypes.Role, userRole));
				}
				var authSignInKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
				var token = new JwtSecurityToken(

					issuer: _configuration["JWT:ValidIssuer"],
					audience: _configuration["JWT:ValidAudience"],
					expires: System.DateTime.Now.AddHours(1),
					claims: authClaims,
					signingCredentials: new SigningCredentials(authSignInKey, SecurityAlgorithms.HmacSha256)
				);
				return Ok(new
				{
					token = new JwtSecurityTokenHandler().WriteToken(token)
				});
			}
			return Unauthorized();
		}
	}
}
