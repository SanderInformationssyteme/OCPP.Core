using OCPP.Core.Tools.Tools;

namespace OCPP.Core.Tools.Extentions
{
    /// <summary>
    /// Provides extension methods for the string class.
    /// </summary>
    public static class StringExtentions
    {
        /// <summary>
        /// Compares a cryptographed password with a plaintext password.
        /// </summary>
        /// <param name="str1">The cryptographed password.</param>
        /// <param name="str2">The plaintext password.</param>
        /// <returns>True if the passwords are equal, false otherwise.</returns>
        public static bool PasswordEqual(this string str1, string str2)
        {
            PasswordCryptographer cryptographer = new PasswordCryptographer();
            return cryptographer.AreEqual(str1, str2);
        }

        /// <summary>
        /// Encrypts a plaintext password.
        /// </summary>
        /// <param name="str1">The plaintext password.</param>
        /// <returns>The encrypted password.</returns>
        public static string EncryptPassword(this string str1)
        {
            PasswordCryptographer cryptographer = new PasswordCryptographer();
            return cryptographer.GenerateSaltedPassword(str1);
        }
    }
}