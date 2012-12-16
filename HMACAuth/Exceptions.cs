using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HMACAuth
{
    public class NoKeyProvidedException : Exception
    {
    }

    public class NoDateProvidedException : Exception
    {
    }

    public class NoHashProvidedEception : Exception
    {
    }

    public class InvalidHeaderException : Exception
    {
        public InvalidHeaderException(string message)
            : base(message)
        {
        }
    }

    public class InvalidSentTimeException : Exception
    {
        public InvalidSentTimeException(string message)
            : base(message)
        {
        }
    }

    public class MultipleUsersException : Exception
    {
    }

    public class NoUsersFoundException : Exception
    {
    }   
}
