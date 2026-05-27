using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace WindowsClient.App.ViewModels;

public sealed class ProfileWizardViewModel : INotifyPropertyChanged
{
    private int currentStep = 1;

    public event PropertyChangedEventHandler? PropertyChanged;

    public int CurrentStep
    {
        get => currentStep;
        set
        {
            if (currentStep == value)
            {
                return;
            }

            currentStep = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CurrentStep)));
        }
    }

    public string[] Steps { get; } =
    [
        "Basic Connection",
        "Network Interface",
        "Security And Advanced Options",
        "Review And Preflight",
    ];
}
