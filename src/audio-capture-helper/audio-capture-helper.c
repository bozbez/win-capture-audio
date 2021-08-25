#include <windows.h>

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <audiopolicy.h>
#include <mmdeviceapi.h>
#include <audioclientactivationparams.h>

#include "../common.h"

#include "audio-capture-helper.h"
#include "format-conversion.h"
#include "uuids.h"

static HRESULT STDMETHODCALLTYPE
dummy_query_interface(IActivateAudioInterfaceCompletionHandler *this,
		      REFIID riid, _COM_Outptr_ void **ppv_object)
{
	*ppv_object = this;
	return S_OK;
}

static ULONG STDMETHODCALLTYPE
dummy_add_release(IActivateAudioInterfaceCompletionHandler *this)
{
	return S_OK;
}

static HRESULT STDMETHODCALLTYPE
activate_completed(IActivateAudioInterfaceCompletionHandler *this,
		   IActivateAudioInterfaceAsyncOperation *operation);

static IActivateAudioInterfaceCompletionHandlerVtbl completion_handler_vtbl = {
	.QueryInterface = dummy_query_interface,
	.AddRef = dummy_add_release,
	.Release = dummy_add_release,
	.ActivateCompleted = activate_completed};

typedef struct completion_handler {
	IActivateAudioInterfaceCompletionHandlerVtbl *lpVtbl;
	IAudioClient *client;

	HANDLE event_finished;
	HRESULT activate_hr;
} completion_handler_t;

static HRESULT STDMETHODCALLTYPE
activate_completed(IActivateAudioInterfaceCompletionHandler *this,
		   IActivateAudioInterfaceAsyncOperation *operation)
{
	completion_handler_t *completion_handler = (completion_handler_t *)this;
	completion_handler->activate_hr = S_OK;

	HRESULT activate_hr = E_FAIL;
	HRESULT hr = E_FAIL;

	hr = CALL(operation, GetActivateResult, &activate_hr,
		  (IUnknown **)&completion_handler->client);

	if (FAILED(hr)) {
		error("failed to get activate result (0x%lx)", hr);
		completion_handler->activate_hr = hr;
	}

	if (FAILED(activate_hr)) {
		error("activate failed (0x%lx)", activate_hr);
		completion_handler->activate_hr = activate_hr;
	}

	SetEvent(completion_handler->event_finished);
	return S_OK;
}

static AUDIOCLIENT_ACTIVATION_PARAMS get_params(DWORD pid, bool include_tree)
{
	int mode = include_tree
			   ? PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE
			   : PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE;

	AUDIOCLIENT_ACTIVATION_PARAMS client_params = {
		.ActivationType = AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
		.ProcessLoopbackParams.TargetProcessId = pid,
		.ProcessLoopbackParams.ProcessLoopbackMode = mode,
	};

	return client_params;
}

static PROPVARIANT get_propvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params)
{
	PROPVARIANT propvariant = {
		.vt = VT_BLOB,
		.blob.cbSize = sizeof(*params),
		.blob.pBlobData = (BYTE *)params,
	};

	return propvariant;
}

static IAudioClient *get_audio_client(DWORD pid, bool include_tree)
{
	audio_uuids_t uuids = get_uuids();

	AUDIOCLIENT_ACTIVATION_PARAMS params = get_params(pid, include_tree);
	PROPVARIANT propvariant = get_propvariant(&params);

	HRESULT hr = E_FAIL;

	IActivateAudioInterfaceAsyncOperation *async_op;
	completion_handler_t completion_handler = {
		.lpVtbl = &completion_handler_vtbl,
		.client = NULL,

		.event_finished = CreateEventW(NULL, FALSE, FALSE, NULL),
		.activate_hr = E_FAIL,
	};

	if (completion_handler.event_finished == NULL) {
		error("failed to create completion event");
		return NULL;
	}

	hr = ActivateAudioInterfaceAsync(
		VIRTUAL_AUDIO_DEVICE_PROCESS_LOOPBACK, &uuids.IID_IAudioClient,
		&propvariant,
		(IActivateAudioInterfaceCompletionHandler *)&completion_handler,
		&async_op);

	if (FAILED(hr)) {
		error("failed to activate audio interface (0x%lx)", hr);
		return NULL;
	}

	WaitForSingleObject(completion_handler.event_finished, INFINITE);
	if (FAILED(completion_handler.activate_hr)) {
		error("activate completion handler failed (0x%lx)",
		      completion_handler.activate_hr);
		SAFE_RELEASE(completion_handler.client);
		return NULL;
	}

	return completion_handler.client;
}

static WAVEFORMATEX *get_default_mix_format()
{
	audio_uuids_t uuids = get_uuids();
	HRESULT hr;

	WAVEFORMATEX *format = NULL;

	IMMDeviceEnumerator *enumerator = NULL;
	hr = CoCreateInstance(&uuids.CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
			      &uuids.IID_IMMDeviceEnumerator,
			      (void **)&enumerator);

	if (FAILED(hr)) {
		error("failed to create device enumerator (0x%lx)", hr);
		goto exit;
	}

	IMMDevice *device = NULL;
	hr = CALL(enumerator, GetDefaultAudioEndpoint, eRender, eMultimedia,
		  &device);

	if (FAILED(hr)) {
		error("failed to get default audio endpoint (0x%lx)", hr);
		goto exit;
	}

	IAudioClient *client = NULL;
	hr = CALL(device, Activate, &uuids.IID_IAudioClient, CLSCTX_ALL, NULL,
		  (void **)&client);

	if (FAILED(hr)) {
		error("failed to activate device (0x%lx)", hr);
		goto exit;
	}

	hr = CALL(client, GetMixFormat, &format);

	if (FAILED(hr)) {
		error("failed to get device mix format (0x%lx)", hr);
		goto exit;
	}

exit:
	SAFE_RELEASE(client);
	SAFE_RELEASE(device);
	SAFE_RELEASE(enumerator);

	return format;
}

static WAVEFORMATEX *setup_audio_client(IAudioClient *client, HANDLE event)
{
	WAVEFORMATEX *format = get_default_mix_format();
	if (format == NULL) {
		error("failed to get default render mix format");
		SAFE_RELEASE(client);
		return NULL;
	}

	HRESULT hr = E_FAIL;
	hr = CALL(client, Initialize, AUDCLNT_SHAREMODE_SHARED,
		  AUDCLNT_STREAMFLAGS_LOOPBACK |
			  AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
		  0, 0, format, NULL);
	if (FAILED(hr)) {
		error("failed to initialize audio client (0x%lx)", hr);
		SAFE_RELEASE(client);
		return NULL;
	}

	hr = CALL(client, SetEventHandle, event);
	if (FAILED(hr)) {
		error("failed to set audio client event handle (0x%lx)", hr);
		SAFE_RELEASE(client);
	}

	return format;
}

static IAudioCaptureClient *get_capture_client(IAudioClient *client)
{
	audio_uuids_t uuids = get_uuids();

	IAudioCaptureClient *capture_client;
	HRESULT hr = CALL(client, GetService, &uuids.IID_IAudioCaptureClient,
			  (void **)&capture_client);

	if (FAILED(hr)) {
		error("failed get capture client (0x%lx)", hr);
		return NULL;
	}

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

static void destroy_helper_data(audio_capture_helper_context_t *ctx)
{
	if (ctx->data != NULL) {
		UnmapViewOfFile((void *)ctx->data);
		ctx->data = NULL;
	}

	safe_close_handle(&ctx->data_map);
}

static bool init_helper_data(audio_capture_helper_context_t *ctx)
{
	wchar_t name[MAX_PATH];
	format_name_tag(name, HELPER_DATA_NAME, ctx->options.tag);

	ctx->data_map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
	if (ctx->data_map == NULL) {
		error("failed to open file mapping with name: %ls", name);
		return false;
	}

	ctx->data = MapViewOfFile(ctx->data_map, FILE_MAP_ALL_ACCESS, 0, 0,
				  sizeof(audio_capture_helper_data_t));
	if (ctx->data == NULL) {
		error("failed to create file map view");
		return false;
	}

	ctx->data->audio.data[0] = (uint8_t *)ctx->data->data;

	ctx->data->audio.speakers =
		get_obs_speaker_layout((WAVEFORMATEXTENSIBLE *)ctx->format);
	ctx->data->audio.format =
		get_obs_format((WAVEFORMATEXTENSIBLE *)ctx->format);
	ctx->data->audio.samples_per_sec = ctx->format->nSamplesPerSec;

	return true;
}

static void destroy_events(audio_capture_helper_context_t *ctx)
{
	for (int i = 0; i < NUM_HELPER_EVENTS_TOTAL; ++i)
		safe_close_handle(&ctx->events[i]);
}

static bool init_events(audio_capture_helper_context_t *ctx)
{
	for (int i = 0; i < NUM_HELPER_EVENTS_TOTAL; ++i) {
		wchar_t name[MAX_PATH];
		format_name_tag(name, event_names[i], ctx->options.tag);

		ctx->events[i] = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE,
					    false, name);

		if (ctx->events[i] == NULL)
			return false;
	}

	return true;
}

static void destroy_context(audio_capture_helper_context_t *ctx)
{
	SAFE_RELEASE(ctx->client);
	SAFE_RELEASE(ctx->capture_client);

	safe_close_handle(&ctx->event_data);

	destroy_helper_data(ctx);
	destroy_events(ctx);
}

static int init_context(audio_capture_helper_context_t *ctx, int argc,
			char *argv[])
{
	int ret = 0;

	ret = parse_options(&ctx->options, argc, argv);
	if (ret != 0) {
		error("failed to parse command line options");
		return ret;
	}

	ctx->client =
		get_audio_client(ctx->options.pid, ctx->options.include_tree);
	if (ctx->client == NULL) {
		error("failed to get audio client");
		ret = 110;
		goto err;
	}

	ctx->event_data = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (ctx->event_data == NULL) {
		error("failed to create data event");
		ret = 111;
		goto err;
	}

	ctx->format = setup_audio_client(ctx->client, ctx->event_data);
	if (ctx->format == NULL) {
		error("failed to setup audio client");
		ret = 112;
		goto err;
	}

	ctx->capture_client = get_capture_client(ctx->client);
	if (ctx->capture_client == NULL) {
		error("failed to get capture client");
		ret = 113;
		goto err;
	}

	if (!init_helper_data(ctx)) {
		error("failed to init helper shmem");
		ret = 114;
		goto err;
	}

	if (!init_events(ctx)) {
		error("failed to init events");
		ret = 115;
		goto err;
	}

	return ret;

err:
	destroy_context(ctx);
	return ret;
}

static bool forward_audio_packet(audio_capture_helper_context_t *ctx)
{
	if (InterlockedCompareExchange(&ctx->data->lock, 1, 0) != 0) {
		warn("failed to acquire data lock");
		return true;
	}

	HRESULT hr;

	ctx->data->audio.frames = 0;
	ctx->data->data_size = 0;

	size_t frame_size =
		(ctx->format->wBitsPerSample * ctx->format->nChannels) /
		CHAR_BIT;

	// Real number obtained from first GetBuffer
	UINT32 num_frames = 1;

	while (num_frames > 0) {
		BYTE *data;
		DWORD flags;
		UINT64 qpc_position;

		hr = CALL(ctx->capture_client, GetBuffer, &data, &num_frames,
			  &flags, NULL, &qpc_position);
		if (FAILED(hr)) {
			warn("capture client getbuffer failed");
			InterlockedExchange(&ctx->data->lock, 0);
			return false;
		}

		// Set timestamp only on first GetBuffer
		if (ctx->data->audio.frames == 0)
			ctx->data->audio.timestamp = qpc_position * 100;

		size_t packet_size = frame_size * num_frames;
		size_t data_start = ctx->data->data_size;

		for (size_t i = 0; i < packet_size; ++i) {
			ctx->data->data[data_start + i] =
				flags & AUDCLNT_BUFFERFLAGS_SILENT ? 0
								   : data[i];
		}

		ctx->data->data_size += packet_size;
		ctx->data->audio.frames += num_frames;

		hr = CALL(ctx->capture_client, ReleaseBuffer, num_frames);
		if (FAILED(hr))
			warn("capture client releasebuffer failed");

		hr = CALL(ctx->capture_client, GetNextPacketSize, &num_frames);
		if (FAILED(hr)) {
			warn("capture client getnextpacketsize failed");
			num_frames = 0;
		}
	}

	InterlockedExchange(&ctx->data->lock, 0);
	SetEvent(ctx->events[HELPER_EVENT_DATA]);

	return true;
}

static bool tick(audio_capture_helper_context_t *ctx, int event_id, int *err)
{
	switch (event_id) {
	case HELPER_WO_EVENT_SHUTDOWN:
		info("shutting down");
		return true;
	case NUM_HELPER_WO_EVENTS: // event_data
		return !forward_audio_packet(ctx);
		break;
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
	HANDLE *events = malloc(num_events * sizeof(HANDLE));
	for (int i = 0; i < NUM_HELPER_WO_EVENTS; ++i)
		events[i] = ctx.events[i];

	events[num_events - 1] = ctx.event_data;

	CALL(ctx.client, Start);

	bool shutdown = false;
	while (!shutdown) {
		int event_id = WaitForMultipleObjects(num_events, events, false,
						      INFINITE);

		if (!(event_id >= WAIT_OBJECT_0 &&
		      event_id < WAIT_OBJECT_0 + num_events)) {
			error("error waiting for events");

			ret = 2;
			shutdown = true;
		}

		shutdown = tick(&ctx, event_id, &ret);
	}

	CALL(ctx.client, Stop);

	free(events);
	destroy_context(&ctx);

	return ret;
}