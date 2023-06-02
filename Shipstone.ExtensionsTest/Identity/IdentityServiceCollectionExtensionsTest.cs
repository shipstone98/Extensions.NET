using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Shipstone.ExtensionsTest.Identity
{
    [TestClass]
    public class IdentityServiceCollectionExtensionsTest
    {
        [TestMethod]
        public void TestAddIdentity_Invalid()
        {
            // Act
            ArgumentException ex =
                Assert.ThrowsException<ArgumentNullException>(() =>
                    Extensions.Identity.IdentityServiceCollectionExtensions.AddIdentity(null));

            // Assert
            Assert.AreEqual(
                "services is null. (Parameter 'services')",
                ex.Message
            );

            Assert.AreEqual("services", ex.ParamName);
        }

        [DataRow(8, 6, false, false, false, false)]
        [DataRow(8, 6, false, false, false, true)]
        [DataRow(8, 6, false, false, true, false)]
        [DataRow(8, 6, false, false, true, true)]
        [DataRow(8, 6, false, true, false, false)]
        [DataRow(8, 6, false, true, false, true)]
        [DataRow(8, 6, false, true, true, false)]
        [DataRow(8, 6, false, true, true, true)]
        [DataRow(8, 6, true, false, false, false)]
        [DataRow(8, 6, true, false, false, true)]
        [DataRow(8, 6, true, false, true, false)]
        [DataRow(8, 6, true, false, true, true)]
        [DataRow(8, 6, true, true, false, false)]
        [DataRow(8, 6, true, true, false, true)]
        [DataRow(8, 6, true, true, true, false)]
        [DataRow(8, 6, true, true, true, true)]
        [TestMethod]
        public void TestAddIdentity_Valid_ConfigurePasswordNotNull(
            int requiredLength,
            int requiredUniqueChars,
            bool requireDigit,
            bool requireLowercase,
            bool requireNonAlphanumeric,
            bool reqireUppercase
        )
        {
            // Arrange
            IServiceCollection services = new ServiceCollection();

            Action<PasswordOptions> configurePassword = options =>
            {
                options.RequireDigit = requireDigit;
                options.RequiredLength = requiredLength;
                options.RequiredUniqueChars = requiredUniqueChars;
                options.RequireLowercase = requireLowercase;
                options.RequireNonAlphanumeric = requireNonAlphanumeric;
                options.RequireUppercase = reqireUppercase;
            };

            // Act
            IServiceCollection result =
                Extensions.Identity.IdentityServiceCollectionExtensions.AddIdentity(
                    services,
                    configurePassword
                );

            // Assert
            Assert.IsTrue(Object.ReferenceEquals(services, result));
            services.AssertIdentityServices(configurePassword);
        }

        [TestMethod]
        public void TestAddIdentity_Valid_ConfigurePasswordNull()
        {
            // Arrange
            IServiceCollection services = new ServiceCollection();

            // Act
            IServiceCollection result =
                Extensions.Identity.IdentityServiceCollectionExtensions.AddIdentity(services);

            // Assert
            Assert.IsTrue(Object.ReferenceEquals(services, result));
            services.AssertIdentityServices();
        }
    }
}
