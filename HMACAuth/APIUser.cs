using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HMACAuth
{
    public class APIUser
    {
        public int ID { get; set; }
        public string Username { get; set; }
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public Role PrivilegeLevel { get; set; }
    }
}
