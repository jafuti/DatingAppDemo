using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Registor(RegisterDto registerDto)
        {

            //Checking wether user exsit or not
            if (await UserExists(registerDto.Username)) return BadRequest("User Name is Taken");

            //Converting
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.AppUsers.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {

            //Checking wether the user exsit or not
            var user = await _context.AppUsers
                   .SingleOrDefaultAsync(x => x.UserName == loginDto.username);

            if (user == null) return Unauthorized("Invalid UserName");

            //computed hash of their password using the password salt 
            using var hmac = new HMACSHA512(user.PasswordSalt);

            //workout for the hash for password in the loginDto

            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));

            for (int i = 0; i < computeHash.Length; i++)
            {
                if (computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");

            }
             return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        //A method to check wether the user exsit or not 
        private async Task<bool> UserExists(string username)
        {
            return await _context.AppUsers.AnyAsync(x => x.UserName == username.ToLower());
        }

    }
}