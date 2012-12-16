using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HMACAuth
{
    public class AuthorizationComponents
    {
        public DateTime TimeRequestExecuted { get; set; }
        public string PublicKey { get; set; }
        public string DataHash { get; set; }
    }
}
