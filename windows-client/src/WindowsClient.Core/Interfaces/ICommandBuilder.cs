using WindowsClient.Core.Models;

namespace WindowsClient.Core.Interfaces;

public interface ICommandBuilder
{
    EdgeCommandModel Build(ProfileModel profile, string resolvedEdgePath);
}
