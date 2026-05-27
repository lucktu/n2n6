using WindowsClient.Core.Models;

namespace WindowsClient.Core.Services;

public sealed class ProfileValidator
{
    public ProfileValidationResult Validate(ProfileModel profile, IEnumerable<string> existingNames)
    {
        var result = new ProfileValidationResult();

        if (string.IsNullOrWhiteSpace(profile.Name))
        {
            result.Errors.Add(new ProfileValidationError
            {
                Code = "Profile.Name.Required",
                Message = "Profile name is required.",
            });
        }

        if (string.IsNullOrWhiteSpace(profile.EdgeVersionId))
        {
            result.Errors.Add(new ProfileValidationError
            {
                Code = "Profile.EdgeVersion.Required",
                Message = "Edge version is required.",
            });
        }

        if (!string.IsNullOrWhiteSpace(profile.Name) && existingNames.Contains(profile.Name, StringComparer.OrdinalIgnoreCase))
        {
            result.Errors.Add(new ProfileValidationError
            {
                Code = "Profile.Name.Duplicate",
                Message = "Profile name must be unique.",
            });
        }

        if (string.IsNullOrWhiteSpace(profile.SupernodeHost))
        {
            result.Errors.Add(new ProfileValidationError
            {
                Code = "Profile.Supernode.Required",
                Message = "Supernode host is required.",
            });
        }

        if (profile.SupernodePort is <= 0 or > 65535)
        {
            result.Errors.Add(new ProfileValidationError
            {
                Code = "Profile.SupernodePort.Invalid",
                Message = "Supernode port must be between 1 and 65535.",
            });
        }

        if (string.IsNullOrWhiteSpace(profile.Community))
        {
            result.Errors.Add(new ProfileValidationError
            {
                Code = "Profile.Community.Required",
                Message = "Community is required.",
            });
        }

        return result;
    }
}
