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
	auto mode = include_tree
			    ? PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE
			    : PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE;

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

void AudioCaptureHelper::InitFormat()
{
	auto enumerator =
		wil::CoCreateInstance<MMDeviceEnumerator, IMMDeviceEnumerator>();

	wil::com_ptr<IMMDevice> device;
	enumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &device);

	wil::com_ptr<IAudioClient> client;
	device->Activate(__uuidof(IAudioClient), CLSCTX_INPROC_SERVER, NULL,
			 client.put_void());

	client->GetMixFormat(wil::out_param(format));

	info("format: ch:%d bps:%lu nbl:%d tag:%d", format->nChannels,
	     format->nAvgBytesPerSec, format->nBlockAlign, format->wFormatTag);
}

void AudioCaptureHelper::InitClient()
{
	auto params = GetParams();
	auto propvariant = GetPropvariant(&params);

	wil::com_ptr<IActivateAudioInterfaceAsyncOperation> async_op;
	CompletionHandler completion_handler;

	THROW_IF_FAILED(ActivateAudioInterfaceAsync(
		VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK, __uuidof(IAudioClient),
		&propvariant, &completion_handler, &async_op));

	completion_handler.event_finished.wait();
	THROW_IF_FAILED(completion_handler.activate_hr);

	client = completion_handler.client;

	client->Initialize(AUDCLNT_SHAREMODE_SHARED,
			   AUDCLNT_STREAMFLAGS_LOOPBACK |
				   AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
			   5 * 10000000, 0, format.get(), NULL);

	client->SetEventHandle(events[HelperEvents::PacketReady].get());
}

void AudioCaptureHelper::InitCapture()
{
	InitFormat();
	InitClient();

	client->GetService(__uuidof(IAudioCaptureClient),
			   capture_client.put_void());
}

void AudioCaptureHelper::Capture()
{
	InitCapture();
	client->Start();

	bool shutdown = false;
	while (!shutdown) {
		auto event_id = WaitForMultipleObjects(
			events.size(), events[0].addressof(), FALSE, INFINITE);
			
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

	client->Stop();
}

void AudioCaptureHelper::ForwardPacket()
{
	obs_source_audio packet = {
		.speakers = get_obs_speaker_layout(format.get()),
		.format = get_obs_format(format.get()),
		.samples_per_sec = format->nSamplesPerSec,
	};

	size_t frame_size = format->nBlockAlign;
	size_t frame_size_packed =
		(format->wBitsPerSample * format->nChannels) / CHAR_BIT;

	UINT32 num_frames = 0;
	capture_client->GetNextPacketSize(&num_frames);

	while (num_frames > 0) {
		BYTE *new_data;
		DWORD flags;
		UINT64 qpc_position;

		capture_client->GetBuffer(&new_data, &num_frames, &flags, NULL,
					  &qpc_position);

		if (!(flags & AUDCLNT_BUFFERFLAGS_SILENT)) {
			packet.timestamp = qpc_position * 100;
			packet.frames = num_frames;

			packet.data[0] = new_data;
			obs_source_output_audio(source, &packet);
		}

		if (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY)
			warn("data discontinuity flag set");

		if (flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR)
			warn("timestamp error flag set");

		capture_client->ReleaseBuffer(num_frames);
		capture_client->GetNextPacketSize(&num_frames);
	}
}

AudioCaptureHelper::AudioCaptureHelper(obs_source_t *source, DWORD pid,
				       bool include_tree)
	: source{source}, pid{pid}, include_tree{include_tree}
{
	for (auto& event : events)
		event.create();

	capture_thread = std::thread(&AudioCaptureHelper::Capture, this);
}

AudioCaptureHelper::~AudioCaptureHelper()
{
	events[HelperEvents::Shutdown].SetEvent();
	capture_thread.join();
}