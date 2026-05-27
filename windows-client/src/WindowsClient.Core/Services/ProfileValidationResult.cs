namespace WindowsClient.Core.Services;

public sealed class ProfileValidationResult
{
    public List<ProfileValidationError> Errors { get; } = new();

    public bool IsValid => Errors.Count == 0;
}

public sealed class ProfileValidationError
{
    public required string Code { get; init; }

    public required string Message { get; init; }
}
