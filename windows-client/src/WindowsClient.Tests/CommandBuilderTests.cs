using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Processes;

namespace WindowsClient.Tests;

public sealed class CommandBuilderTests
{
    [Fact]
    public void Build_ShouldIncludeSelectedVersionInputsInGeneratedArguments()
    {
        var builder = new CommandBuilder();
        var profile = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
            TapName = "tap-ops",
            IPv4AddressWithPrefix = "static:192.168.10.5/24",
            PlaintextKey = "secret",
        };

        var command = builder.Build(profile, resolvedEdgePath: "bin\\v26\\edge.exe");

        Assert.Contains("-c", command.Arguments);
        Assert.Contains("ops", command.Arguments);
        Assert.Contains("-l", command.Arguments);
        Assert.Contains("vpn.example.com:1234", command.Arguments);
    }

    [Fact]
    public void Build_ShouldMaskPlaintextKeyInPreview()
    {
        var builder = new CommandBuilder();
        var profile = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
            PlaintextKey = "secret",
        };

        var command = builder.Build(profile, resolvedEdgePath: "bin\\v26\\edge.exe");

        Assert.DoesNotContain("secret", command.MaskedPreview, StringComparison.Ordinal);
        Assert.Contains("***", command.MaskedPreview, StringComparison.Ordinal);
    }
}
