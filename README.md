# win-capture-audio

![overview](https://raw.githubusercontent.com/bozbez/win-capture-audio/main/media/overview.png)

An OBS plugin based on OBS's win-capture/game-capture that hooks WASAPI's audio output functions (rather than the various graphics API funcitons) that enables capture of audio streams directly from applications. This eliminates the need for third-party software or hardware audio mixing tools that introduce complexity, and in the case of software tools introduce mandatory latency.

The modus operandi is identical to the aforementioned game-capture plugin (and most likely to Discord's solution), and is inherently liable to instability and other issues due to the lack of a more "official" solution from the Windows API.

DISCLAIMER: I am not able to guarantee that using this is anti-cheat safe, however similar hook methods are employed in many widely deployed applications (Discord, Steam Overlay, RTSS, NVIDIA's ShadowPlay, etc...).

## Limitations (current)

- WASAPI only (no DirectSound, WaveOut, etc...)
- No Windows App support (probably?)
- Chrome and Chrome-based (e.g. Electron) applications don't work (probably a limitation of the process selection logic rather than the hooking)
- Directly conflicts with Discord streaming (and maybe ShadowPlay) (unresolvable?)
- Dodgy batch script installer

## Installation and Usage

1. Head over to the [Releases](https://github.com/bozbez/win-capture-audio/releases) page and download the latest installation package
2. If your OBS is in the default location in `Program Files` then run the aptly-named `install.bat` with administrator privileges, otherwise copy `win-capture-audio.dll` and `win-capture-audio.pdb` to `obs-studio/obs-plugins/64bit` and the contents of `data` to `obs-studio/data/obs-plugins/win-capture-audio` creating the folder if necessary
3. Lauch OBS and check out the newly available "Application Audio Output Capture" source