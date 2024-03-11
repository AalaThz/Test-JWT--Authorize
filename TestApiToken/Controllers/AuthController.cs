using BCrypt.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestApiToken.Models;

namespace TestApiToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        //برای استفاده از appsetting باید سازنده را فراخوانی کنیم. 
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("register")]
        public ActionResult<User> Register(UserDto requst)
        {
            //تبدیل رمز به هش کد
            string passwordHash 
                = BCrypt.Net.BCrypt.HashPassword(requst.Password);
            //Generate hashCod password password
            //اینجا یک رمز به صورت رشته میگیرد و معادلش یک هش کد تولید میکند
            user.UserName = requst.UserName;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        //اگر کاربری در دیتابیس باشد آن را با داده دیتابیس مقایسه میکنیم.
        //ولی اینجا برای اموزش api از داده ی خودمان استفاده کردیم
        [HttpPost("Login")]
        public ActionResult<User> Login(UserDto requst)
        {
            //چک کردن یوزر نیم با مقدار وارد شده یا مقدار در دیتابیس
            if (user.UserName != requst.UserName)
            {
                return BadRequest("User not found!");
            }
            //چک کردن رمز با مقدار وارد شده یا در دیتابیس
            if (!BCrypt.Net.BCrypt.Verify(requst.Password , user.PasswordHash))
            {
                return BadRequest("wrong pasword");
            }

            //return Ok(user);  //قبل از نوشتن متد

            string token = CreateToken(user);  //بعد از نوشتن متد زیر اضافه شد
            return Ok(token);
        }
        
        //call a private method to create token
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
            };

            //Generate token web JSON manualy
            //تولید یک توکن وب جیسون به صورت دستی
            //ابتدا نیاز به یک کلید امنیتی متقارن داریم
            //باید رفرنس Microsoft.IdentityModel.Tokens نصب شود
            //SymmetricSecurityKeyاین یک کلید است که برای ایجاد توکن وب جیسون نیاز به یک رشته بایتی دارد 
            //var key = new SymmetricSecurityKey()
            //میتوانیم رشته را در appsetting.jason بسازیم
            //هر زمان یوزر تماس برقرار کند یا برنامه با توکن وب جیسون تماس برقرار کند، رمز وب جیسون را تایید میکند
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value!));
            //با انکدینگ دوباره این را رمز نگاری میکنیم

            //حالا به اعتبار نامه های امضا نیاز داریم
            //signin credentials
            //درونش از key و الگورتمی که می خواهیم برای توکن وب جیسون خود استفاده کنیم را مینویسیم
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //Generate our token
            var token = new JwtSecurityToken(
                    claims : claims,
                    expires : DateTime.Now.AddDays(1),  //ست کردن زمان منقضی شدن توکن
                    signingCredentials : creds     //اعتبارنامه امضا
                );

            //مرحله آخر نوشتن توکن است و برای آن JWT خود را ذخیره میکنیم. 
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

    }
}
