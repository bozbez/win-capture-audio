#include <functional>
#include <windows.h>

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <vector>
#include <stdexcept>

#include <wil/result.h>
#include <wil/result_macros.h>

#include "audio-capture-helper.hpp"
#include "format-conversion.hpp"

AUDIOCLIENT_ACTIVATION_PARAMS AudioCaptureHelper::GetParams()
{
	auto mode = PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE;

	return {
		.ActivationType = AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
		.ProcessLoopbackParams =
			{
				.TargetProcessId = pid,
				.ProcessLoopbackMode = mode,
			},
	};
}

PROPVARIANT
AudioCaptureHelper::GetPropvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params)
{
	return {
		.vt = VT_BLOB,
		.blob =
			{
				.cbSize = sizeof(*params),
				.pBlobData = (BYTE *)params,
			},
	};
}

void AudioCaptureHelper::InitClient()
{
	auto params = GetParams();
	auto propvariant = GetPropvariant(&params);

	wil::com_ptr<IActivateAudioInterfaceAsyncOperation> async_op;
	CompletionHandler completion_handler;

	THROW_IF_FAILED(ActivateAudioInterfaceAsync(VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK,
						    __uuidof(IAudioClient), &propvariant,
						    &completion_handler, &async_op));

	completion_handler.event_finished.wait();
	THROW_IF_FAILED(completion_handler.activate_hr);

	client = completion_handler.client;

	THROW_IF_FAILED(
		client->Initialize(AUDCLNT_SHAREMODE_SHARED,
				   AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
				   5 * 10000000, 0, &format, NULL));

	THROW_IF_FAILED(client->SetEventHandle(events[HelperEvents::PacketReady].get()));
}

void AudioCaptureHelper::InitCapture()
{
	InitClient();
	THROW_IF_FAILED(
		client->GetService(__uuidof(IAudioCaptureClient), capture_client.put_void()));
}

void AudioCaptureHelper::RegisterMixer(Mixer *mixer)
{
	auto lock = mixers_section.lock();
	mixers.insert(mixer);
}

bool AudioCaptureHelper::UnRegisterMixer(Mixer *mixer)
{
	auto lock = mixers_section.lock();
	mixers.erase(mixer);

	return mixers.size() == 0;
}

void AudioCaptureHelper::ForwardToMixers(UINT64 qpc_position, BYTE *data, UINT32 num_frames)
{
	auto lock = mixers_section.lock();

	for (auto *mixer : mixers)
		mixer->SubmitPacket(qpc_position, reinterpret_cast<float *>(data), num_frames);
}

void AudioCaptureHelper::ForwardPacket()
{
	size_t frame_size = format.nBlockAlign;

	UINT32 num_frames = 0;
	THROW_IF_FAILED(capture_client->GetNextPacketSize(&num_frames));

	while (num_frames > 0) {
		BYTE *new_data;
		DWORD flags;
		UINT64 qpc_position;

		THROW_IF_FAILED(capture_client->GetBuffer(&new_data, &num_frames, &flags, NULL,
							  &qpc_position));

		if (!(flags & AUDCLNT_BUFFERFLAGS_SILENT))
			ForwardToMixers(qpc_position, new_data, num_frames);

		if (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY)
			warn("data discontinuity flag set");

		if (flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR)
			warn("timestamp error flag set");

		THROW_IF_FAILED(capture_client->ReleaseBuffer(num_frames));
		THROW_IF_FAILED(capture_client->GetNextPacketSize(&num_frames));
	}
}

void AudioCaptureHelper::Capture()
{
	InitCapture();
	THROW_IF_FAILED(client->Start());

	bool shutdown = false;
	while (!shutdown) {
		auto event_id = WaitForMultipleObjects(events.size(), events[0].addressof(), FALSE,
						       INFINITE);

		switch (event_id) {
		case HelperEvents::PacketReady:
			ForwardPacket();
			break;

		case HelperEvents::Shutdown:
			shutdown = true;
			break;

		default:
			error("wait failed with result: %d", event_id);
			shutdown = true;
			break;
		}
	}

	THROW_IF_FAILED(client->Stop());
}

void AudioCaptureHelper::CaptureSafe()
{
	try {
		Capture();
	} catch (wil::ResultException e) {
		error("%s", e.what());
	}
}

AudioCaptureHelper::AudioCaptureHelper(Mixer *mixer, WAVEFORMATEX format, DWORD pid)
	: mixers{mixer}, format{format}, pid{pid}
{
	for (auto &event : events)
		event.create();

	capture_thread = std::thread(&AudioCaptureHelper::CaptureSafe, this);
}

AudioCaptureHelper::~AudioCaptureHelper()
{
	auto lock = mixers_section.lock();
	mixers.clear();
	lock.reset();

	events[HelperEvents::Shutdown].SetEvent();
	capture_thread.join();
}