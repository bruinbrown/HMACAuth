using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HMACAuth
{
    public static class HashProviderFactory
    {
        public static KeyedHashAlgorithm GetInstance(SecurityProvider provider)
        {
            switch (provider)
            {
                case SecurityProvider.HMACMD5:
                    return new HMACMD5();
                case SecurityProvider.HMACRIPEMD160:
                    return new HMACRIPEMD160();
                case SecurityProvider.HMACSHA1:
                    return new HMACSHA1();
                case SecurityProvider.HMACSHA256:
                    return new HMACSHA256();
                case SecurityProvider.HAMCSHA384:
                    return new HMACSHA384();
                case SecurityProvider.HMACSHA512:
                    return new HMACSHA512();
                default:
                    return new HMACMD5();
            }
        }
    }
}
