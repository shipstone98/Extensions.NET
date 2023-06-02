using System;

namespace Shipstone.Extensions.Identity
{
    /// <summary>
    /// Provides methods for validating, hashing, and verifying passwords.
    /// </summary>
    public interface IPasswordService
    {
        /// <summary>
        /// Hashes the specified password.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <returns>The hashed representation of <c><paramref name="password" /></c>.</returns>
        /// <exception cref="ArgumentNullException"><c><paramref name="password" /></c> is <c>null</c>.</exception>
        String Hash(String password);

        /// <summary>
        /// Validates the specified password.
        /// </summary>
        /// <param name="password">The password to validate.</param>
        /// <returns><c>true</c> if <c><paramref name="password" /></c> is a valid password; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><c><paramref name="password" /></c> is <c>null</c>.</exception>
        bool Validate(String password);

        /// <summary>
        /// Verifies the specified password against the specified password hash.
        /// </summary>
        /// <param name="passwordHash">The password hash to verify <c><paramref name="password" /></c> against.</param>
        /// <param name="password">The password to verify against <c><paramref name="passwordHash" /></c>.</param>
        /// <param name="isRehashRequired">When this method returns, <c>true</c> if <c><paramref name="passwordHash" /></c> was hashed using a less secure algorithm and should be hashed again; otherwise, <c>false</c>. The value is always <c>false</c> when this method returns <c>false</c>. This parameter is passed unintialized.</param>
        /// <returns><c>true</c> if <c><paramref name="passwordHash" /></c> represents a password hash that matches the hashed representation of <c><paramref name="password" /></c>; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><c><paramref name="passwordHash" /></c> is <c>null</c> -or- <c><paramref name="password" /></c> is <c>null</c>.</exception>
        bool Verify(
            String passwordHash,
            String password,
            out bool isRehashRequired
        );
    }
}
