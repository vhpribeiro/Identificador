using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Identificador.API
{
    public class SigningConfigurations
    {
        public SecurityKey Key { get; }
        public SigningCredentials SigningCredentials { get; }

        public SigningConfigurations()
        {
            Key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("secrekeysecrekeysecrekey"));
            SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256Signature);
        }
    }
}