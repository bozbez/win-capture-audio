# win-capture-audio

An OBS plugin based on OBS's win-capture/game-capture that hooks WASAPI's audio output functions (rather than the various graphics API funcitons) that enables capture of audio streams directly from applications. This eliminates the need for third-party software or hardware audio mixing tools that introduce complexity, and in the case of software tools introduce mandatory latency.

The modus operandi is identical to the aforementioned game-capture plugin (and most likely to Discord's solution), and is inherently liable to instability and other issues due to the lack of a more "official" solution from the Windows API.

WARNING: I am not able to guarantee that using this is anti-cheat safe, however similar hook methods are employed in many widely deployed applications (Discord, Steam Overlay, RTSS, NVIDIA's ShadowPlay, etc...).

![overview](https://raw.githubusercontent.com/bozbez/win-capture-audio/main/media/overview.png)

## Limitations (current)

- WASAPI only (no DirectSound, WaveOut, etc...)
- No Windows App support (probably?)
- Chrome and Chrome-based (e.g. Electron) applications don't work (probably a limitation of the process selection logic rather than the hooking)
- Directly conflicts with Discord streaming (and maybe ShadowPlay) (unresolvable?)

## Installation and Usage

1. Head over to the [Releases](https://github.com/bozbez/win-capture-audio/releases) page and download the latest installer (or zip if you are using a portable installation)
2. Run the setup wizard, selecting your OBS folder when asked (or extract the zip to the portable OBS root directory)
3. Lauch OBS and check out the newly available "Application Audio Output Capture" source
4. Enjoy Streaming and Recording
