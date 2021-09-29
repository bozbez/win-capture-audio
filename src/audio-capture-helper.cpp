#include <array>
#include <windows.h>

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <vector>
#include <stdexcept>

#include <wil/result.h>

#include "audio-capture-helper.h"
#include "format-conversion.h"
#include "wil/result_macros.h"

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

	event_data.create();
	client->SetEventHandle(event_data.get());
}

void AudioCaptureHelper::InitCapture()
{
	InitFormat();
	InitClient();

	client->GetService(__uuidof(IAudioCaptureClient),
			   capture_client.put_void());

	DWORD task_id = 0;
	THROW_IF_FAILED(
		MFLockSharedWorkQueue(L"Capture", 0, &task_id, &queue_id));
	callback_packet_ready.SetQueueId(queue_id);

	event_result_shutdown.create();
	THROW_IF_FAILED(MFCreateAsyncResult(nullptr, &callback_packet_ready,
					    nullptr, &packet_ready_result));
}

HRESULT AudioCaptureHelper::OnPacketReady(IMFAsyncResult *result)
{
	auto requeue_callback = wil::scope_exit([&]() {
		MFPutWaitingWorkItem(event_data.get(), 0,
				     packet_ready_result.get(),
				     &packet_ready_key);
	});

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

	return S_OK;
}

AudioCaptureHelper::AudioCaptureHelper(obs_source_t *source, DWORD pid,
				       bool include_tree)
	: source{source}, pid{pid}, include_tree{include_tree}
{
	InitCapture();
	THROW_IF_FAILED(MFPutWaitingWorkItem(event_data.get(), 0,
					     packet_ready_result.get(),
					     &packet_ready_key));

	client->Start();
}

AudioCaptureHelper::~AudioCaptureHelper()
{
	client->Stop();
	THROW_IF_FAILED(MFCancelWorkItem(packet_ready_key));

	packet_ready_result.reset();
	event_result_shutdown.wait();

	MFUnlockWorkQueue(queue_id);
}