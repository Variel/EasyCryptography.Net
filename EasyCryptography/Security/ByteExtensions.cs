using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Variel.Security
{
    public static class ByteExtensions
    {
        public static string ToShortString(this byte[] input)
        {
            return Convert.ToBase64String(input).Replace("=", "");
        }
    }
}
