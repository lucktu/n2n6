using WindowsClient.Core.Interfaces;
using WindowsClient.Core.Models;
using WindowsClient.Core.Services;

namespace WindowsClient.Infrastructure.Processes;

public sealed class CommandBuilder : ICommandBuilder
{
    private readonly CommandPreviewMasker masker = new();

    public EdgeCommandModel Build(ProfileModel profile, string resolvedEdgePath)
    {
        var args = new List<string>();

        if (!string.IsNullOrWhiteSpace(profile.TapName))
        {
            args.AddRange(new[] { "-d", profile.TapName });
        }

        if (!string.IsNullOrWhiteSpace(profile.Community))
        {
            args.AddRange(new[] { "-c", profile.Community });
        }

        if (!string.IsNullOrWhiteSpace(profile.PlaintextKey))
        {
            args.AddRange(new[] { "-k", profile.PlaintextKey });
        }

        if (!string.IsNullOrWhiteSpace(profile.IPv4AddressWithPrefix))
        {
            args.AddRange(new[] { "-a", profile.IPv4AddressWithPrefix });
        }

        if (!string.IsNullOrWhiteSpace(profile.IPv6AddressWithPrefix))
        {
            args.AddRange(new[] { "-A", profile.IPv6AddressWithPrefix });
        }

        if (!string.IsNullOrWhiteSpace(profile.MacAddress))
        {
            args.AddRange(new[] { "-m", profile.MacAddress });
        }

        if (!string.IsNullOrWhiteSpace(profile.SupernodeHost) && profile.SupernodePort > 0)
        {
            args.AddRange(new[] { "-l", $"{profile.SupernodeHost}:{profile.SupernodePort}" });
        }

        if (string.Equals(profile.ResolutionMode, "ipv4", StringComparison.OrdinalIgnoreCase))
        {
            args.Add("-4");
        }
        else if (string.Equals(profile.ResolutionMode, "ipv6", StringComparison.OrdinalIgnoreCase))
        {
            args.Add("-6");
        }

        if (profile.AcceptMulticast)
        {
            args.Add("-E");
        }

        if (profile.EnableRouting)
        {
            args.Add("-r");
        }

        if (profile.ManagementPort is > 0)
        {
            args.AddRange(new[] { "-t", profile.ManagementPort.Value.ToString() });
        }

        if (!string.IsNullOrWhiteSpace(profile.ExtraArgs))
        {
            args.AddRange(profile.ExtraArgs.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        var rawPreview = string.Join(' ', new[] { resolvedEdgePath }.Concat(args));

        return new EdgeCommandModel
        {
            ExecutablePath = resolvedEdgePath,
            Arguments = args,
            RawPreview = rawPreview,
            MaskedPreview = masker.MaskSecret(rawPreview, profile.PlaintextKey),
        };
    }
}
