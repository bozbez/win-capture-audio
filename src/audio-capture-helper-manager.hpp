#pragma once

#include <unordered_map>
#include <tuple>
#include <set>

#include <windows.h>

#include <wil/resource.h>

#include "common.hpp"
#include "audio-capture-helper.hpp"

class AudioCaptureHelperManager {
private:
	wil::critical_section helpers_section;
	std::unordered_map<DWORD, AudioCaptureHelper> helpers;

	WAVEFORMATEX format;

public:
	AudioCaptureHelperManager()
	{
		obs_audio_info info;
		obs_get_audio_info(&info);

		format.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
		format.nChannels = info.speakers;
		format.nSamplesPerSec = info.samples_per_sec;

		format.nBlockAlign = format.nChannels * sizeof(float);
		format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
		format.wBitsPerSample = CHAR_BIT * sizeof(float);
		format.cbSize = 0;
	};

	~AudioCaptureHelperManager() = default;

	WAVEFORMATEX GetFormat() { return format; }

	void RegisterMixer(DWORD pid, Mixer *mixer)
	{
		auto lock = helpers_section.lock();

		try {
			auto [it, inserted] = helpers.try_emplace(pid, mixer, format, pid);
			if (!inserted)
				it->second.RegisterMixer(mixer);
		} catch (wil::ResultException e) {
			error("failed to create helper... update Windows?");
			error("%s", e.what());
		}
	};

	void UnRegisterMixer(DWORD pid, Mixer *mixer)
	{
		auto lock = helpers_section.lock();

		auto it = helpers.find(pid);
		if (it == helpers.end())
			return;

		auto remove_helper = it->second.UnRegisterMixer(mixer);
		if (remove_helper)
			helpers.erase(it);
	};
};