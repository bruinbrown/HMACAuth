using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HMACAuth
{
    public enum SecurityProvider
    {
        HMACSHA1,
        HMACSHA256,
        HAMCSHA384,
        HMACSHA512,
        HMACMD5,
        HMACRIPEMD160
    }
}
