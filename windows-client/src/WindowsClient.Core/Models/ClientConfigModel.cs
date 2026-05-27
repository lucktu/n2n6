namespace WindowsClient.Core.Models;

public sealed class ClientConfigModel
{
    public List<ProfileModel> Profiles { get; set; } = new();

    public AppStateModel AppState { get; set; } = new();
}
