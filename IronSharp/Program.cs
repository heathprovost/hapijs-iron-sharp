using System;

namespace IronSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            var plaintext = "foo";
            var password = "passwordpasswordpasswordpassword";
            var token = IronSharp.Seal(plaintext, password, IronSharp.DEFAULTS);
            var unsealed = IronSharp.Unseal(token, password, IronSharp.DEFAULTS);
            Console.WriteLine(token);
            Console.WriteLine(unsealed);
            Console.ReadKey();
        }
    }
}
