using System.Security.Cryptography;

namespace OCPP.Core.Tools.Tools
{
	/// <summary>
	/// This class is used for password encryption and decryption using a specific cryptographic algorithm.
	/// </summary>
	/// <remarks>
	/// This class is taken from the DevExpress Library. With this class, encrypted passwords can be checked.
	/// </remarks>
	public class PasswordCryptographer
	{
		/// <summary>
		/// The length of the salt that is appended to the password. This is the length of the salted password.
		/// </summary>
		private const int SaltLength = 6;

		/// <summary>
		/// A delimiter between the salted password and the password, to distinguish both components.
		/// </summary>
		private const string DelimiterSalt = "*";

		/// <summary>
		/// Generates a new password using a hash algorithm and an additional component.
		/// </summary>
		/// <param name="password">The password to be encrypted.</param>
		/// <returns>The encrypted password.</returns>
		public virtual string GenerateSaltedPassword(string password)
		{
			if (string.IsNullOrEmpty(password))
			{
				return password;
			}

			byte[] randomSalt = RandomNumberGenerator.GetBytes(SaltLength);
			string salt = Convert.ToBase64String(randomSalt);

			return salt + DelimiterSalt + this.SaltPassword(password, salt);
		}

		/// <summary>
		/// Checks a password.
		/// </summary>
		/// <param name="saltedPassword">The encrypted password.</param>
		/// <param name="password">The password entered by the user.</param>
		/// <returns>True if the passwords match; false otherwise.</returns>
		public virtual bool AreEqual(string saltedPassword, string password)
		{
			if (string.IsNullOrEmpty(saltedPassword))
			{
				return string.IsNullOrEmpty(password);
			}

			if (string.IsNullOrEmpty(password))
			{
				return false;
			}

			int delimPos = saltedPassword.IndexOf(DelimiterSalt);
			if (delimPos <= 0)
			{
				return saltedPassword.Equals(password);
			}

			string calculatedSaltedPassword = this.SaltPassword(password, saltedPassword.Substring(0, delimPos));
			string expectedSaltedPassword = saltedPassword.Substring(delimPos + DelimiterSalt.Length);
			if (expectedSaltedPassword.Equals(calculatedSaltedPassword))
			{
				return true;
			}

			return expectedSaltedPassword.Equals(this.SaltPassword(password, "System.Byte[]"));
		}

		/// <summary>
		/// Generates the additional "salty" part of the password.
		/// </summary>
		/// <param name="password">The new password.</param>
		/// <param name="salt">The existing additional part of the password.</param>
		/// <returns>The encrypted password of the additional part.</returns>
		private string SaltPassword(string password, string salt)
		{
			SHA512 hashAlgorithm = SHA512.Create();
			return Convert.ToBase64String(hashAlgorithm.ComputeHash(System.Text.Encoding.UTF8.GetBytes(salt + password)));
		}
	}
}