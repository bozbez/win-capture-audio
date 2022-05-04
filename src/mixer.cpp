#include "mixer.hpp"
#include "format-conversion.hpp"
#include "wil/result_macros.h"
#include <basetsd.h>
#include <memory>
#include <processthreadsapi.h>
#include <threadpoollegacyapiset.h>
#include <winbase.h>
#include <winuser.h>

template<typename T> T Mixer::RoundToNearest(T x, T m)
{
	return ((x + m / 2) / m) * m;
}

UINT64 Mixer::GetCurrentTimestamp()
{
	LARGE_INTEGER timestamp_ticks;
	static LARGE_INTEGER frequency = {0};

	if (frequency.QuadPart == 0)
		QueryPerformanceFrequency(&frequency);

	QueryPerformanceCounter(&timestamp_ticks);
	return timestamp_ticks.QuadPart * (10000000 / frequency.QuadPart);
}

std::size_t Mixer::DurationToFrames(UINT64 duration)
{
	UINT64 duration_ns = duration * 100;
	return (duration_ns * format.nSamplesPerSec) / 1000000000;
}

UINT64 Mixer::FramesToDuration(std::size_t frames)
{
	UINT64 duration_ns = (frames * 1000000000) / format.nSamplesPerSec;
	return duration_ns / 100;
}

void Mixer::ProcessInput(UINT64 input_timestamp, std::vector<float> &input_buffer)
{
	if (mix.size() == 0) {
		mix_timestamp = input_timestamp;
		mix = std::move(input_buffer);

		return;
	}

	if (input_timestamp < mix_timestamp) {
		warn("late mix input packet - increase cutoff_end?");
		return;
	}

	auto offset = format.nChannels * DurationToFrames(input_timestamp - mix_timestamp);

	if (offset + input_buffer.size() > mix.size())
		mix.resize(offset + input_buffer.size());

	for (std::size_t i = 0; i < input_buffer.size(); ++i)
		mix[offset + i] += input_buffer[i];
}

void Mixer::ProcessInput()
{
	auto lock = input_section.lock();

	while (input_queue.size() > 0) {
		auto &[input_timestamp, input_buffer] = input_queue.front();
		ProcessInput(input_timestamp, input_buffer);
		input_queue.pop();
	}
}

std::size_t Mixer::TimestampToMixOffset(UINT64 timestamp)
{
	if (timestamp < mix_timestamp)
		return 0;

	return min(mix.size() / format.nChannels, DurationToFrames(timestamp - mix_timestamp));
}

std::tuple<std::size_t, std::size_t> Mixer::CalculateCutoff(UINT64 timestamp)
{
	if (timestamp < cutoff_end)
		return {0, 0};

	if (timestamp < cutoff_start)
		return {0, TimestampToMixOffset(timestamp - cutoff_end)};

	auto start = TimestampToMixOffset(timestamp - cutoff_start);
	auto end = TimestampToMixOffset(timestamp - cutoff_end);

	return {start, end};
}

void Mixer::Tick()
{
	ProcessInput();

	if (mix.size() == 0)
		return;

	UINT64 current_timestamp = GetCurrentTimestamp();
	auto [start, end] = CalculateCutoff(current_timestamp);

	if (start * format.nChannels >= mix.size()) {
		mix.clear();
		return;
	} else if (end - start == 0)
		return;

	obs_source_audio obs_packet = {
		.frames = static_cast<UINT32>(end - start),
		.speakers = get_obs_speaker_layout(&format),
		.format = get_obs_format(&format),
		.samples_per_sec = format.nSamplesPerSec,
		.timestamp = (mix_timestamp + FramesToDuration(start)) * 100,
	};

	obs_packet.data[0] = reinterpret_cast<BYTE *>(mix.data() + start * format.nChannels);
	obs_source_output_audio(source, &obs_packet);

	std::vector<float> new_mix(mix.begin() + end * format.nChannels, mix.end());
	mix = std::move(new_mix);

	mix_timestamp += FramesToDuration(end);
}

void Mixer::Run()
{
	// Force message queue creation
	MSG msg;
	PeekMessageA(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

	worker_ready.SetEvent();

	bool shutdown = false;
	while (!shutdown) {
		if (!GetMessage(&msg, reinterpret_cast<HWND>(-1), WM_USER, 0)) {
			debug("shutting down");
			shutdown = true;
		}

		switch (msg.message) {
		case MixerEvents::Shutdown:
			debug("shutting down");
			shutdown = true;
			break;

		case MixerEvents::Tick:
			Tick();
			break;
		}
	}
}

void Mixer::SubmitPacket(UINT64 timestamp, float *data, UINT32 num_frames)
{
	auto lock = input_section.lock();

	auto &[_, buffer] = input_queue.emplace(timestamp, 0);
	buffer.assign(data, data + num_frames * format.nChannels);

	lock.reset();
}

static void CALLBACK post_tick(PVOID param, BOOLEAN)
{
	auto worker_tid = reinterpret_cast<intptr_t>(param);
	PostThreadMessageW(worker_tid, MixerEvents::Tick, NULL, NULL);
}

Mixer::Mixer(obs_source_t *source, WAVEFORMATEX format) : source{source}, format{format}
{
	worker_thread = std::thread(&Mixer::Run, this);
	worker_tid = GetThreadId(worker_thread.native_handle());

	int64_t tid_64 = worker_tid;

	SetThreadPriority(worker_thread.native_handle(), THREAD_PRIORITY_HIGHEST);
	CreateTimerQueueTimer(&timer, NULL, post_tick, reinterpret_cast<void *>(tid_64),
			      tick_interval, tick_interval, WT_EXECUTEINTIMERTHREAD);
}

Mixer::~Mixer()
{
	DeleteTimerQueueTimer(NULL, timer, INVALID_HANDLE_VALUE);

	worker_ready.wait();
	PostThreadMessageW(worker_tid, MixerEvents::Shutdown, NULL, NULL);
	worker_thread.join();
}
