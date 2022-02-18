#pragma once

#include <windows.h>
#include <mmreg.h>

#include <obs.h>

static inline enum speaker_layout get_obs_speaker_layout(WAVEFORMATEX *format)
{
	auto format_ex = reinterpret_cast<WAVEFORMATEXTENSIBLE *>(format);

	switch (format_ex->Format.nChannels) {
	case 1:
		return SPEAKERS_MONO;
	case 2:
		return SPEAKERS_STEREO;
	case 3:
		return SPEAKERS_2POINT1;
	case 4:
		return SPEAKERS_4POINT0;
	case 5:
		return SPEAKERS_4POINT1;
	case 6:
		return SPEAKERS_5POINT1;
	case 8:
		return SPEAKERS_7POINT1;
	}

	return SPEAKERS_UNKNOWN;
}

static inline enum audio_format get_obs_pcm_format(int bits_per_sample)
{
	switch (bits_per_sample) {
	case 8:
		return AUDIO_FORMAT_U8BIT;
	case 16:
		return AUDIO_FORMAT_16BIT;
	case 32:
		return AUDIO_FORMAT_32BIT;
	};

	return AUDIO_FORMAT_UNKNOWN;
}

static inline enum audio_format get_obs_format(WAVEFORMATEX *format)
{
	auto format_ex = reinterpret_cast<WAVEFORMATEXTENSIBLE *>(format);

	switch (format_ex->Format.wFormatTag) {
	case WAVE_FORMAT_PCM:
		return get_obs_pcm_format(format_ex->Format.wBitsPerSample);

	case WAVE_FORMAT_IEEE_FLOAT:
		return AUDIO_FORMAT_FLOAT;

	case WAVE_FORMAT_EXTENSIBLE:
		if (format_ex->SubFormat == KSDATAFORMAT_SUBTYPE_PCM) {
			return get_obs_pcm_format(format_ex->Format.wBitsPerSample);
		} else if (format_ex->SubFormat == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT) {
			return AUDIO_FORMAT_FLOAT;
		}
	}

	return AUDIO_FORMAT_UNKNOWN;
}