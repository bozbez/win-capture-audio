#include <windows.h>

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <vector>
#include <stdexcept>

#include <wil/result.h>

#include "../common.h"

#include "audio-capture-helper.hpp"
#include "format-conversion.hpp"
#include "wil/result_macros.h"

AUDIOCLIENT_ACTIVATION_PARAMS AudioCaptureHelper::GetParams()
{
	auto mode = options.include_tree
			    ? PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE
			    : PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE;

	return {
		.ActivationType = AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
		.ProcessLoopbackParams =
			{
				.TargetProcessId = options.pid,
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

	wchar_t name[MAX_PATH];
	format_name_tag(name, HELPER_EVENT_DATA_NAME, options.tag);
	event_data_forward.open(name);
}

void AudioCaptureHelper::InitData()
{
	wchar_t name[MAX_PATH];
	format_name_tag(name, HELPER_DATA_NAME, options.tag);

	data_map = wil::unique_handle(
		OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name));

	if (!data_map) {
		error("failed to open file mapping with name: %ls", name);
		return;
	}

	auto data_void = MapViewOfFile(data_map.get(), FILE_MAP_ALL_ACCESS, 0,
				       0, sizeof(audio_capture_helper_data_t));

	data = wil::unique_mapview_ptr<audio_capture_helper_data_t>(
		(audio_capture_helper_data_t *)data_void);

	if (!data) {
		error("failed to create file map view");
		return;
	}

	data->speakers =
		get_obs_speaker_layout((WAVEFORMATEXTENSIBLE *)format.get());
	data->format = get_obs_format((WAVEFORMATEXTENSIBLE *)format.get());
	data->samples_per_sec = format->nSamplesPerSec;
}

void AudioCaptureHelper::InitCapture()
{
	InitFormat();
	InitClient();

	client->GetService(__uuidof(IAudioCaptureClient),
			   capture_client.put_void());

	THROW_IF_FAILED(MFStartup(MF_VERSION, MFSTARTUP_LITE));

	DWORD task_id = 0;
	THROW_IF_FAILED(
		MFLockSharedWorkQueue(L"Capture", 0, &task_id, &queue_id));
	callback_packet_ready.SetQueueId(queue_id);

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

	if (InterlockedCompareExchange(&data->lock, 1, 0) != 0) {
		warn("failed to acquire data lock");
		return S_OK;
	}

	auto unlock_and_forward = wil::scope_exit([&]() {
		InterlockedExchange(&data->lock, 0);
		event_data_forward.SetEvent();
	});

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

		int cur_packet = data->num_packets++;
		data->timestamp[cur_packet] = qpc_position * 100;

		bool silent = flags & AUDCLNT_BUFFERFLAGS_SILENT;
		for (size_t i = 0; i < num_frames; ++i) {
			size_t pos = i * frame_size;
			size_t pos_packed = i * frame_size_packed;

			for (size_t j = 0; j < frame_size_packed; ++j) {
				data->data[cur_packet][pos_packed + j] =
					silent ? 0 : new_data[pos + j];
			}
		}

		data->data_size[cur_packet] = frame_size_packed * num_frames;
		data->frames[cur_packet] = num_frames;

		capture_client->ReleaseBuffer(num_frames);
		capture_client->GetNextPacketSize(&num_frames);
	}

	return S_OK;
}

void AudioCaptureHelper::Start()
{
	THROW_IF_FAILED(MFPutWaitingWorkItem(event_data.get(), 0,
					     packet_ready_result.get(),
					     &packet_ready_key));

	client->Start();
}

void AudioCaptureHelper::Stop()
{
	client->Stop();
	THROW_IF_FAILED(MFCancelWorkItem(packet_ready_key));
}

CaptureOptions::CaptureOptions(int argc, char *argv[])
{
	if (argc != 4)
		throw std::runtime_error("wrong number of arguments");

	pid = strtoul(argv[1], NULL, 0);
	if (pid == 0)
		throw std::runtime_error("failed to parse PID");

	if (strcmp("include", argv[2]) == 0)
		include_tree = true;
	else if (strcmp("exclude", argv[2]) == 0)
		include_tree = false;
	else
		throw std::runtime_error("failed to parse mode");

	tag = argv[3];
	if (strlen(tag) < 1)
		throw std::runtime_error("failed to parse tag");
}

void run(CaptureOptions options)
{
	wchar_t name[MAX_PATH];
	format_name_tag(name, HELPER_WO_EVENT_SHUTDOWN_NAME, options.tag);

	wil::unique_event event_shutdown;
	event_shutdown.open(name);

	AudioCaptureHelper helper(options);

	helper.Start();
	event_shutdown.wait();
	helper.Stop();
}

int main(int argc, char *argv[])
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		error("failed to initialize COM runtime");
		return 1;
	}

	try {
		run(CaptureOptions(argc, argv));
	} catch (wil::ResultException err) {
		error("%s", err.what());
		return err.GetErrorCode();
	} catch (std::runtime_error err) {
		error("%s", err.what());
		return 1;
	}

	CoUninitialize();
	return 0;
}