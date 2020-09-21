using System;

namespace IronSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            var plaintext = "{\"foo\":\"bar\"}";
            var password = new IronPassword("foo","passwordpasswordpasswordpassword");
            var passwords = new IronPassword[] { new IronPassword("foo", "passwordpasswordpasswordpassword") };
            var token = Iron.Seal(plaintext, password, Iron.DEFAULTS);
            var unsealed = Iron.Unseal(token, passwords, Iron.DEFAULTS);
            Console.WriteLine(token);
            Console.WriteLine(unsealed);
            Console.ReadKey();
        }
    }
}
