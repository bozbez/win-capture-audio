# win-capture-audio

An OBS plugin similar to OBS's win-capture/game-capture that allows for audio capture from a specific application, rather than the system's audio as a whole. This eliminates the need for third-party software or hardware audio mixing tools that introduce complexity, and in the case of software tools, introduce mandatory latency.

Internally it uses [ActivateAudioInterfaceAsync](https://docs.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-activateaudiointerfaceasync) with [AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS](https://docs.microsoft.com/en-us/windows/win32/api/audioclientactivationparams/ns-audioclientactivationparams-audioclient_process_loopback_params). This initialization structure is only officially available on Windows 11, however it appears to work additionally on relatively recent versions of Windows 10.

**This plugin is in a BETA state, expect issues - [https://discord.gg/4D5Yk5gFnM](https://discord.gg/4D5Yk5gFnM) for support and updates.**<br/>
**An updated version of Windows 10 2004 (released 2020-05-27) or later is required.**

![overview](https://raw.githubusercontent.com/bozbez/win-capture-audio/main/media/overview.png)

## Installation and Usage

1. Head over to the [Releases](https://github.com/bozbez/win-capture-audio/releases) page and download the latest installer (or zip if you are using a portable installation)
2. Run the setup wizard, selecting your OBS folder when asked (or extract the zip to the portable OBS root directory)
3. Launch OBS and check out the newly available "Application Audio Output Capture" source
