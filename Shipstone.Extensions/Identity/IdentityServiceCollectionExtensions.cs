using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Shipstone.Extensions.Identity
{
    /// <summary>
    /// Provides extension methods for registering identity services with instances of <see cref="IServiceCollection" />.
    /// </summary>
    public static class IdentityServiceCollectionExtensions
    {
        /// <summary>
        /// Registers identity services with the specified <see cref="IServiceCollection" />.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to register identity services with.</param>
        /// <param name="configurePassword">An action delegate to configure the provided <see cref="PasswordOptions" />, or <c>null</c>.</param>
        /// <returns>A reference to <c><paramref name="services" /></c> so that additional calls can be chained.</returns>
        /// <exception cref="ArgumentNullException"><c><paramref name="services" /></c> is <c>null</c>.</exception>
        public static IServiceCollection AddIdentity(
            this IServiceCollection services,
            Action<PasswordOptions> configurePassword = null
        )
        {
            if (services is null)
            {
                throw new ArgumentNullException(
                    nameof (services),
                    $"{nameof (services)} is null."
                );
            }

            PasswordOptions passwordOptions = new PasswordOptions();

            if (!(configurePassword is null))
            {
                configurePassword(passwordOptions);
            }

            services.AddSingleton(passwordOptions);
            services.AddSingleton<IPasswordHasher<Object>, PasswordHasher<Object>>();
            services.AddSingleton<IPasswordService, PasswordService>();
            return services;
        }
    }
}
