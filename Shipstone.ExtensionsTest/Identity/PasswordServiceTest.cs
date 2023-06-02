using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Shipstone.Extensions.Identity;

namespace Shipstone.ExtensionsTest.Identity
{
    [TestClass]
    public class PasswordServiceTest
    {
        private static IPasswordService Build(Action<PasswordOptions>? configurePassword = null)
        {
            IServiceCollection services = new ServiceCollection();
            services.AddIdentity(configurePassword);
            IServiceProvider provider = services.BuildServiceProvider();
            return provider.GetRequiredService<IPasswordService>();
        }

        [TestMethod]
        public void TestHash_Invalid()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();

            // Act
            ArgumentException ex =
                Assert.ThrowsException<ArgumentNullException>(() =>
                    service.Hash(null));

            // Assert
            Assert.AreEqual(
                "password is null. (Parameter 'password')",
                ex.Message
            );

            Assert.AreEqual("password", ex.ParamName);
        }

        [TestMethod]
        public void TestHash_Valid()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();
            IPasswordHasher<Object> hasher = new PasswordHasher<Object>();
            const String PASSWORD = "P@ssw0rd";

            // Act
            String passwordHash = service.Hash(PASSWORD);

            // Assert
            Assert.AreEqual(
                PasswordVerificationResult.Success,
                hasher.VerifyHashedPassword(hasher, passwordHash, PASSWORD)
            );
        }

#region Validate method
#region Invalid parameters
        [TestMethod]
        public void TestValidate_Invalid_Empty()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();

            // Act
            ArgumentException ex =
                Assert.ThrowsException<ArgumentException>(() =>
                    service.Validate(String.Empty));

            // Assert
            Assert.AreEqual(
                "password is empty or consists only of white-space characters. (Parameter 'password')",
                ex.Message
            );

            Assert.AreEqual("password", ex.ParamName);
        }

        [TestMethod]
        public void TestValidate_Invalid_Null()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();

            // Act
            ArgumentException ex =
                Assert.ThrowsException<ArgumentNullException>(() =>
                    service.Validate(null));

            // Assert
            Assert.AreEqual(
                "password is null. (Parameter 'password')",
                ex.Message
            );

            Assert.AreEqual("password", ex.ParamName);
        }

        [TestMethod]
        public void TestValidate_Invalid_WhiteSpace()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();

            foreach (char c in Internals._WhiteSpace)
            {
                String password = c.ToString();

                // Act
                ArgumentException ex =
                    Assert.ThrowsException<ArgumentException>(() =>
                        service.Validate(password));

                // Assert
                Assert.AreEqual(
                    "password is empty or consists only of white-space characters. (Parameter 'password')",
                    ex.Message
                );

                Assert.AreEqual("password", ex.ParamName);
            }
        }
#endregion

        [DataRow(0, 0, false, false, false, false, "a", true)]
        [DataRow(8, 6, false, false, false, false, "abcdefg", false)]
        [DataRow(8, 6, false, false, false, false, "aaaaaaaa", false)]
        [DataRow(8, 6, false, false, false, false, "abcdefgh", true)]
        [DataRow(8, 6, false, false, false, true, "password", false)]
        [DataRow(8, 6, false, false, false, true, "PASSWORD", true)]
        [DataRow(8, 6, false, false, true, false, "password", false)]
        [DataRow(8, 6, false, false, true, false, "p@ssword", true)]
        [DataRow(8, 6, false, false, true, true, "PASSWORD", false)]
        [DataRow(8, 6, false, false, true, true, "!@£$%^&*", false)]
        [DataRow(8, 6, false, false, true, true, "P@SSWORD", true)]
        [DataRow(8, 6, false, true, false, false, "PASSWORD", false)]
        [DataRow(8, 6, false, true, false, false, "password", true)]
        [DataRow(8, 6, false, true, false, true, "PASSWORD", false)]
        [DataRow(8, 6, false, true, false, true, "password", false)]
        [DataRow(8, 6, false, true, false, true, "Password", true)]
        [DataRow(8, 6, false, true, true, false, "password", false)]
        [DataRow(8, 6, false, true, true, false, "!@£$%^&*", false)]
        [DataRow(8, 6, false, true, true, false, "p@ssword", true)]
        [DataRow(8, 6, false, true, true, true, "PASSWORD", false)]
        [DataRow(8, 6, false, true, true, true, "!@£$%^&*", false)]
        [DataRow(8, 6, false, true, true, true, "password", false)]
        [DataRow(8, 6, false, true, true, true, "P@ssword", true)]
        [DataRow(8, 6, true, false, false, false, "password", false)]
        [DataRow(8, 6, true, false, false, false, "12345678", true)]
        [DataRow(8, 6, true, false, false, true, "PASSWORD", false)]
        [DataRow(8, 6, true, false, false, true, "12345678", false)]
        [DataRow(8, 6, true, false, false, true, "PASSW0RD", true)]
        [DataRow(8, 6, true, false, true, false, "12345678", false)]
        [DataRow(8, 6, true, false, true, false, "!@£$%^&*", false)]
        [DataRow(8, 6, true, false, true, false, "1234!@£$", true)]
        [DataRow(8, 6, true, false, true, true, "12345678", false)]
        [DataRow(8, 6, true, false, true, true, "!@£$%^&*", false)]
        [DataRow(8, 6, true, false, true, true, "PASSWORD", false)]
        [DataRow(8, 6, true, false, true, true, "P@SSW0RD", true)]
        [DataRow(8, 6, true, true, false, false, "12345678", false)]
        [DataRow(8, 6, true, true, false, false, "password", false)]
        [DataRow(8, 6, true, true, false, false, "passw0rd", true)]
        [DataRow(8, 6, true, true, false, true, "12345678", false)]
        [DataRow(8, 6, true, true, false, true, "PASSWORD", false)]
        [DataRow(8, 6, true, true, false, true, "password", false)]
        [DataRow(8, 6, true, true, false, true, "Passw0rd", true)]
        [DataRow(8, 6, true, true, true, false, "12345678", false)]
        [DataRow(8, 6, true, true, true, false, "password", false)]
        [DataRow(8, 6, true, true, true, false, "!@£$%^&*", false)]
        [DataRow(8, 6, true, true, true, false, "p@ssw0rd", true)]
        [DataRow(8, 6, true, true, true, true, "12345678", false)]
        [DataRow(8, 6, true, true, true, true, "PASSWORD", false)]
        [DataRow(8, 6, true, true, true, true, "!@£$%^&*", false)]
        [DataRow(8, 6, true, true, true, true, "password", false)]
        [DataRow(8, 6, true, true, true, true, "P@ssw0rd", true)]
        [TestMethod]
        public void TestValidate_Valid(
            int requiredLength,
            int requiredUniqueChars,
            bool requireDigit,
            bool requireLowercase,
            bool requireNonAlphanumeric,
            bool reqireUppercase,
            String password,
            bool isValid
        )
        {
            // Arrange
            Action<PasswordOptions> configurePassword = options =>
            {
                options.RequireDigit = requireDigit;
                options.RequiredLength = requiredLength;
                options.RequiredUniqueChars = requiredUniqueChars;
                options.RequireLowercase = requireLowercase;
                options.RequireNonAlphanumeric = requireNonAlphanumeric;
                options.RequireUppercase = reqireUppercase;
            };

            IPasswordService service =
                PasswordServiceTest.Build(configurePassword);

            // Act
            bool result = service.Validate(password);

            // Assert
            Assert.AreEqual(isValid, result);
        }
#endregion

#region Verify method
        [TestMethod]
        public void TestVerify_Invalid_PasswordNull()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();
            const String PASSWORD = "P@ssw0rd";
            String passwordHash = service.Hash(PASSWORD);

            // Act
            ArgumentException ex =
                Assert.ThrowsException<ArgumentNullException>(() =>
                    service.Verify(passwordHash, null, out bool _));

            // Assert
            Assert.AreEqual(
                "password is null. (Parameter 'password')",
                ex.Message
            );

            Assert.AreEqual("password", ex.ParamName);
        }

        [TestMethod]
        public void TestVerify_Invalid_PasswordHashNull()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();
            const String PASSWORD = "P@ssw0rd";

            // Act
            ArgumentException ex =
                Assert.ThrowsException<ArgumentNullException>(() =>
                    service.Verify(null, PASSWORD, out bool _));

            // Assert
            Assert.AreEqual(
                "passwordHash is null. (Parameter 'passwordHash')",
                ex.Message
            );

            Assert.AreEqual("passwordHash", ex.ParamName);
        }

#region Valid parameters
        [TestMethod]
        public void TestVerify_Valid_Correct_RehashNotRequired()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();
            const String PASSWORD = "P@ssw0rd";
            String passwordHash = service.Hash(PASSWORD);

            // Act
            bool result = service.Verify(
                passwordHash,
                PASSWORD,
                out bool isRehashRequired
            );

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(isRehashRequired);
        }

        [TestMethod]
        public void TestVerify_Valid_Correct_RehashRequired()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();
            const String PASSWORD = "P@ssw0rd";
            String passwordHash = service.Hash(PASSWORD);

            // Act
            bool result = service.Verify(
                passwordHash,
                PASSWORD,
                out bool isRehashRequired
            );

            // Assert
            Assert.IsTrue(result);
            Assert.IsTrue(isRehashRequired);
        }

        [TestMethod]
        public void TestVerify_Valid_NotCorrect()
        {
            // Arrange
            IPasswordService service = PasswordServiceTest.Build();
            const String PASSWORD_1 = "P@ssw0rd";
            const String PASSWORD_2 = "P@ssw0rd123";
            String passwordHash = service.Hash(PASSWORD_1);

            // Act
            bool result = service.Verify(
                passwordHash,
                PASSWORD_2,
                out bool isRehashRequired
            );

            // Assert
            Assert.IsFalse(result);
            Assert.IsFalse(isRehashRequired);
        }
#endregion
#endregion
    }
}
