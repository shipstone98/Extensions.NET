using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Identity;

namespace Shipstone.Extensions.Identity
{
    internal class PasswordService : IPasswordService
    {
        private readonly IPasswordHasher<Object> _Hasher;
        private readonly PasswordOptions _Options;

        public PasswordService(
            IPasswordHasher<Object> hasher,
            PasswordOptions options
        )
        {
            if (hasher is null)
            {
                throw new ArgumentNullException(
                    nameof (hasher),
                    $"{nameof (hasher)} is null."
                );
            }

            if (options is null)
            {
                throw new ArgumentNullException(
                    nameof (options),
                    $"{nameof (options)} is null."
                );
            }

            this._Hasher = hasher;
            this._Options = options;
        }

        String IPasswordService.Hash(String password)
        {
            if (password is null)
            {
                throw new ArgumentNullException(
                    nameof (password),
                    $"{nameof (password)} is null."
                );
            }

            return this._Hasher.HashPassword(this._Hasher, password);
        }

        bool IPasswordService.Validate(String password)
        {
            if (password is null)
            {
                throw new ArgumentNullException(
                    nameof (password),
                    $"{nameof (password)} is null."
                );
            }

            password = password.Trim();

            if (String.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException(
                    $"{nameof (password)} is empty or consists only of white-space characters.",
                    nameof (password)
                );
            }

            if (password.Length < this._Options.RequiredLength)
            {
                return false;
            }

            if (this._Options.RequireDigit)
            {
                if (!password.Any(c => Char.IsDigit(c)))
                {
                    return false;
                }
            }

            if (this._Options.RequireLowercase)
            {
                if (!password.Any(c => Char.IsLower(c)))
                {
                    return false;
                }
            }

            if (this._Options.RequireNonAlphanumeric)
            {
                if (!password.Any(c => !Char.IsLetterOrDigit(c)))
                {
                    return false;
                }
            }

            if (this._Options.RequireUppercase)
            {
                if (!password.Any(c => Char.IsUpper(c)))
                {
                    return false;
                }
            }

            IReadOnlyCollection<char> characters = new HashSet<char>(password);
            return characters.Count >= this._Options.RequiredUniqueChars;
        }

        bool IPasswordService.Verify(
            String passwordHash,
            String password,
            out bool isRehashRequired
        )
        {
            if (passwordHash is null)
            {
                throw new ArgumentNullException(
                    nameof (passwordHash),
                    $"{nameof (passwordHash)} is null."
                );
            }

            if (password is null)
            {
                throw new ArgumentNullException(
                    nameof (password),
                    $"{nameof (password)} is null."
                );
            }

            PasswordVerificationResult result =
                this._Hasher.VerifyHashedPassword(
                    this._Hasher,
                    passwordHash,
                    password
                );

            if (result == PasswordVerificationResult.Failed)
            {
                return (isRehashRequired = false);
            }
            
            isRehashRequired =
                result == PasswordVerificationResult.SuccessRehashNeeded;

            return true;
        }
    }
}
