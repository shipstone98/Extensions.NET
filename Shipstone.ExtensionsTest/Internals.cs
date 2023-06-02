using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Shipstone.Extensions.Identity;

namespace Shipstone.ExtensionsTest
{
    internal static class Internals
    {
        internal static readonly IReadOnlySet<char> _WhiteSpace;

        static Internals()
        {
            HashSet<char> whiteSpace = new();

            for (int i = Char.MinValue; i <= Char.MaxValue; i ++)
            {
                char c = (char) i;

                if (Char.IsWhiteSpace(c))
                {
                    whiteSpace.Add(c);
                }
            }

            Internals._WhiteSpace = whiteSpace;
        }

        internal static void AssertIdentityServices(
            this IServiceCollection services,
            Action<PasswordOptions>? configurePasswordOptions = null
        )
        {
            PasswordOptions passwordOptions = new();
            IServiceProvider provider = services.BuildServiceProvider();

            if (configurePasswordOptions is not null)
            {
                configurePasswordOptions(passwordOptions);
            }

            PasswordOptions registeredPasswordOptions =
                provider.GetRequiredService<PasswordOptions>();

            IPasswordService registeredPasswordService =
                provider.GetRequiredService<IPasswordService>();

            Assert.AreEqual(
                passwordOptions.RequireDigit,
                registeredPasswordOptions.RequireDigit
            );

            Assert.AreEqual(
                passwordOptions.RequiredLength,
                registeredPasswordOptions.RequiredLength
            );

            Assert.AreEqual(
                passwordOptions.RequiredUniqueChars,
                registeredPasswordOptions.RequiredUniqueChars
            );

            Assert.AreEqual(
                passwordOptions.RequireLowercase,
                registeredPasswordOptions.RequireLowercase
            );

            Assert.AreEqual(
                passwordOptions.RequireNonAlphanumeric,
                registeredPasswordOptions.RequireNonAlphanumeric
            );

            Assert.AreEqual(
                passwordOptions.RequireUppercase,
                registeredPasswordOptions.RequireUppercase
            );
        }
    }
}