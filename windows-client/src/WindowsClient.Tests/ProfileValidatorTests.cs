using WindowsClient.Core.Models;
using WindowsClient.Core.Services;

namespace WindowsClient.Tests;

public sealed class ProfileValidatorTests
{
    [Fact]
    public void Validate_ShouldFail_WhenNameIsMissing()
    {
        var validator = new ProfileValidator();
        var profile = new ProfileModel
        {
            Name = string.Empty,
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
        };

        var result = validator.Validate(profile, existingNames: Array.Empty<string>());

        Assert.Contains(result.Errors, error => error.Code == "Profile.Name.Required");
    }

    [Fact]
    public void Validate_ShouldFail_WhenVersionIsMissing()
    {
        var validator = new ProfileValidator();
        var profile = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = string.Empty,
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
        };

        var result = validator.Validate(profile, existingNames: Array.Empty<string>());

        Assert.Contains(result.Errors, error => error.Code == "Profile.EdgeVersion.Required");
    }

    [Fact]
    public void Validate_ShouldFail_WhenNameDuplicatesAnotherProfile()
    {
        var validator = new ProfileValidator();
        var profile = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
        };

        var result = validator.Validate(profile, existingNames: new[] { "Office" });

        Assert.Contains(result.Errors, error => error.Code == "Profile.Name.Duplicate");
    }
}
