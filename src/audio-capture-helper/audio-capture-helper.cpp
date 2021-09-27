#include <windows.h>

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <vector>

#include <audiopolicy.h>
#include <mmdeviceapi.h>
#include <audioclientactivationparams.h>

#include <wrl/implements.h>
#include <wil/com.h>
#include <wil/result.h>

#include "../common.h"

#include "audio-capture-helper.hpp"
#include "format-conversion.hpp"

using namespace Microsoft::WRL;

struct CompletionHandler
	: public RuntimeClass<RuntimeClassFlags<ClassicCom>, FtmBase,
			      IActivateAudioInterfaceCompletionHandler> {
	wil::com_ptr<IAudioClient> client;

	HRESULT activate_hr = E_FAIL;
	wil::unique_event event_finished;

	CompletionHandler() { event_finished.create(); }

	STDMETHOD(ActivateCompleted)
	(IActivateAudioInterfaceAsyncOperation *operation)
	{
		auto set_finished = event_finished.SetEvent_scope_exit();

		RETURN_IF_FAILED(operation->GetActivateResult(
			&activate_hr, client.put_unknown()));

		if (FAILED(activate_hr))
			error("activate failed (0x%lx)", activate_hr);

		return S_OK;
	}
};

static AUDIOCLIENT_ACTIVATION_PARAMS get_params(DWORD pid, bool include_tree)
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

static PROPVARIANT get_propvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params)
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

static wil::com_ptr<IAudioClient> get_audio_client(DWORD pid, bool include_tree)
{
	auto params = get_params(pid, include_tree);
	auto propvariant = get_propvariant(&params);

	wil::com_ptr<IActivateAudioInterfaceAsyncOperation> async_op;
	CompletionHandler completion_handler;

	THROW_IF_FAILED(ActivateAudioInterfaceAsync(
		VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK, __uuidof(IAudioClient),
		&propvariant, &completion_handler, &async_op));

	completion_handler.event_finished.wait();
	THROW_IF_FAILED(completion_handler.activate_hr);

	return completion_handler.client;
}

static wil::unique_cotaskmem_ptr<WAVEFORMATEX> get_default_mix_format()
{
	auto enumerator =
		wil::CoCreateInstance<MMDeviceEnumerator, IMMDeviceEnumerator>();

	wil::com_ptr<IMMDevice> device;
	enumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &device);

	wil::com_ptr<IAudioClient> client;
	device->Activate(__uuidof(IAudioClient), CLSCTX_INPROC_SERVER, NULL,
			 client.put_void());

	wil::unique_cotaskmem_ptr<WAVEFORMATEX> format;
	client->GetMixFormat(wil::out_param(format));

	return format;
}

static wil::unique_cotaskmem_ptr<WAVEFORMATEX>
setup_audio_client(wil::com_ptr<IAudioClient> client,
		   const wil::unique_event &event)
{
	auto format = get_default_mix_format();
	info("format pre-init: ch:%d bps:%lu nbl:%d tag:%d", format->nChannels,
	     format->nAvgBytesPerSec, format->nBlockAlign, format->wFormatTag);

	client->Initialize(AUDCLNT_SHAREMODE_SHARED,
			   AUDCLNT_STREAMFLAGS_LOOPBACK |
				   AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
			   5 * 10000000, 0, format.get(), NULL);

	client->SetEventHandle(event.get());
	return format;
}

static wil::com_ptr<IAudioCaptureClient>
get_capture_client(wil::com_ptr<IAudioClient> client)
{
	wil::com_ptr<IAudioCaptureClient> capture_client;
	client->GetService(__uuidof(IAudioCaptureClient),
			   capture_client.put_void());

	return capture_client;
}

static int parse_options(capture_options_t *options, int argc, char *argv[])
{
	if (argc != 4)
		return 100;

	options->pid = strtoul(argv[1], NULL, 0);
	if (options->pid == 0)
		return 101;

	if (strcmp("include", argv[2]) == 0)
		options->include_tree = true;
	else if (strcmp("exclude", argv[2]) == 0)
		options->include_tree = false;
	else
		return 102;

	options->tag = argv[3];
	if (strlen(options->tag) < 1)
		return 103;

	return 0;
}

static bool init_helper_data(audio_capture_helper_context_t *ctx)
{
	wchar_t name[MAX_PATH];
	format_name_tag(name, HELPER_DATA_NAME, ctx->options.tag);

	ctx->data_map = wil::unique_handle(
		OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name));

	if (ctx->data_map == NULL) {
		error("failed to open file mapping with name: %ls", name);
		return false;
	}

	auto data = MapViewOfFile(ctx->data_map.get(), FILE_MAP_ALL_ACCESS, 0,
				  0, sizeof(audio_capture_helper_data_t));

	ctx->data = wil::unique_mapview_ptr<audio_capture_helper_data_t>(
		(audio_capture_helper_data_t *)data);

	if (!ctx->data) {
		error("failed to create file map view");
		return false;
	}

	ctx->data->speakers = get_obs_speaker_layout(
		(WAVEFORMATEXTENSIBLE *)ctx->format.get());
	ctx->data->format =
		get_obs_format((WAVEFORMATEXTENSIBLE *)ctx->format.get());
	ctx->data->samples_per_sec = ctx->format->nSamplesPerSec;

	return true;
}

static void init_events(audio_capture_helper_context_t *ctx)
{
	for (int i = 0; i < NUM_HELPER_EVENTS_TOTAL; ++i) {
		wchar_t name[MAX_PATH];
		format_name_tag(name, event_names[i], ctx->options.tag);

		ctx->events[i].open(name);
	}
}

static int init_context(audio_capture_helper_context_t *ctx, int argc,
			char *argv[])
{

	int ret = parse_options(&ctx->options, argc, argv);
	if (ret != 0) {
		error("failed to parse command line options");
		return ret;
	}

	ctx->client =
		get_audio_client(ctx->options.pid, ctx->options.include_tree);

	ctx->event_data.create();
	ctx->format = setup_audio_client(ctx->client, ctx->event_data);
	ctx->capture_client = get_capture_client(ctx->client);

	if (!init_helper_data(ctx)) {
		error("failed to init helper shmem");
		return 114;
	}

	init_events(ctx);
	return 0;
}

static void forward_audio_packet(audio_capture_helper_context_t *ctx)
{
	if (InterlockedCompareExchange(&ctx->data->lock, 1, 0) != 0) {
		warn("failed to acquire data lock");
		return;
	}

	auto cleanup = wil::scope_exit([&]() {
		InterlockedExchange(&ctx->data->lock, 0);
		ctx->events[HELPER_EVENT_DATA].SetEvent();
	});

	size_t frame_size = ctx->format->nBlockAlign;
	size_t frame_size_packed =
		(ctx->format->wBitsPerSample * ctx->format->nChannels) /
		CHAR_BIT;

	UINT32 num_frames = 0;
	ctx->capture_client->GetNextPacketSize(&num_frames);

	while (num_frames > 0) {
		BYTE *data;
		DWORD flags;
		UINT64 qpc_position;

		ctx->capture_client->GetBuffer(&data, &num_frames, &flags, NULL,
					       &qpc_position);

		int cur_packet = ctx->data->num_packets++;
		ctx->data->timestamp[cur_packet] = qpc_position * 100;

		bool silent = flags & AUDCLNT_BUFFERFLAGS_SILENT;
		for (size_t i = 0; i < num_frames; ++i) {
			size_t pos = i * frame_size;
			size_t pos_packed = i * frame_size_packed;

			for (size_t j = 0; j < frame_size_packed; ++j) {
				ctx->data->data[cur_packet][pos_packed + j] =
					silent ? 0 : data[pos + j];
			}
		}

		ctx->data->data_size[cur_packet] =
			frame_size_packed * num_frames;
		ctx->data->frames[cur_packet] = num_frames;

		ctx->capture_client->ReleaseBuffer(num_frames);
		ctx->capture_client->GetNextPacketSize(&num_frames);
	}
}

static bool tick(audio_capture_helper_context_t *ctx, int event_id, int *err)
{
	switch (event_id) {
	case HELPER_WO_EVENT_SHUTDOWN:
		info("shutting down");
		return true;
	case NUM_HELPER_WO_EVENTS: // event_data
		forward_audio_packet(ctx);
		return false;
	default:
		error("unexpected event id: %d", event_id);
		*err = 4;
		return true;
	}

	return false;
}

int main(int argc, char *argv[])
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		error("failed to initialize COM runtime");
		return 1;
	}

	int ret = 0;

	audio_capture_helper_context_t ctx;
	ret = init_context(&ctx, argc, argv);
	if (ret != 0) {
		error("failed to init context");
		return ret;
	}

	info("capture initialized");

	int num_events = 1 + NUM_HELPER_WO_EVENTS;

	std::vector<HANDLE> events;
	for (int i = 0; i < NUM_HELPER_WO_EVENTS; ++i)
		events.push_back(ctx.events[i].get());

	events.push_back(ctx.event_data.get());

	ctx.client->Start();

	bool shutdown = false;
	while (!shutdown) {
		int event_id = WaitForMultipleObjects(num_events, events.data(),
						      false, INFINITE);

		if (!(event_id >= WAIT_OBJECT_0 &&
		      event_id < WAIT_OBJECT_0 + num_events)) {
			error("error waiting for events");

			ret = 2;
			shutdown = true;
		}

		shutdown = tick(&ctx, event_id, &ret);
	}

	ctx.client->Stop();

	return ret;
}