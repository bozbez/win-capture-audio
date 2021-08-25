# win-capture-audio

An OBS plugin similar to OBS's win-capture/game-capture that uses [ActivateAudioInterfaceAsync](https://docs.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-activateaudiointerfaceasync) with [AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS](https://docs.microsoft.com/en-us/windows/win32/api/audioclientactivationparams/ns-audioclientactivationparams-audioclient_process_loopback_params) to capture audio output from a specific process (and optionally its tree of child processes). This eliminates the need for third-party software or hardware audio mixing tools that introduce complexity, and in the case of software tools introduce mandatory latency.

**This plugin requires an updated version of Windows 10 2004 (released 2020-05-27) or later.**

![overview](https://raw.githubusercontent.com/bozbez/win-capture-audio/main/media/overview.png)

## Installation and Usage

1. Head over to the [Releases](https://github.com/bozbez/win-capture-audio/releases) page and download the latest installer (or zip if you are using a portable installation)
2. Run the setup wizard, selecting your OBS folder when asked (or extract the zip to the portable OBS root directory)
3. Lauch OBS and check out the newly available "Application Audio Output Capture" source