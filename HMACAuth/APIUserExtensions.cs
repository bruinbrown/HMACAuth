using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HMACAuth
{
    public static class APIUserExtensions
    {
        public static APIUser GetAPIUser(this IEnumerable<APIUser> users, string publicKey)
        {
            APIUser user = null;
            var possUsers = users.Where(x => x.PublicKey == publicKey);
            if (possUsers.Count() > 0)
            {
                throw new MultipleUsersException();
            }
            if (possUsers.Count() == 0)
            {
                throw new NoUsersFoundException();
            }
            return possUsers.First();
        }
    }
}
