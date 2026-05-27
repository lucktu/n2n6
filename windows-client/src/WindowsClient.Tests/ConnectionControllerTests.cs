using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Processes;

namespace WindowsClient.Tests;

public sealed class ConnectionControllerTests
{
    [Fact]
    public async Task StartAsync_ShouldRejectSecondActiveProfileWithoutReplacement()
    {
        var controller = new ConnectionController();
        var first = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
        };
        var second = new ProfileModel
        {
            Name = "Lab",
            EdgeVersionId = "v3",
            SupernodeHost = "lab.example.com",
            SupernodePort = 1234,
            Community = "lab",
        };

        await controller.MarkRunningForTestAsync(first);

        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.StartAsync(second, replaceActive: false, CancellationToken.None));
    }
}
