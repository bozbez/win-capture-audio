#pragma once

#include <stdio.h>
#include <functional>

#include <windows.h>

#include <audiopolicy.h>
#include <audioclient.h>
#include <audioclientactivationparams.h>
#include <mmdeviceapi.h>

#include <mfapi.h>
#include <mfobjects.h>

#include <wrl/implements.h>
#include <wil/com.h>

#include "../common.h"

#define do_log(format, ...) fprintf(stderr, format, ##__VA_ARGS__)

#define error(format, ...) \
	do_log("error: (%s): " format "\n", __func__, ##__VA_ARGS__)
#define warn(format, ...) \
	do_log("warn: (%s): " format "\n", __func__, ##__VA_ARGS__)
#define info(format, ...) \
	do_log("info: (%s): " format "\n", __func__, ##__VA_ARGS__)
#define debug(format, ...) \
	do_log("debug: (%s): " format "\n", __func__, ##__VA_ARGS__)

struct CaptureOptions {
	DWORD pid;
	bool include_tree;

	char *tag;

	CaptureOptions(int argc, char *argv[]);
};

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

struct AsyncCallbackInvoker : public RuntimeClass<RuntimeClassFlags<ClassicCom>,
						  FtmBase, IMFAsyncCallback> {
	using func_type = std::function<HRESULT(IMFAsyncResult *)>;
	func_type func;
	DWORD queue_id = MFASYNC_CALLBACK_QUEUE_MULTITHREADED;

	AsyncCallbackInvoker(func_type func) : func{func} {}

	STDMETHOD(GetParameters)(DWORD *flags, DWORD *queue)
	{
		*flags = 0;
		*queue = queue_id;
		return S_OK;
	}

	STDMETHOD(Invoke)(IMFAsyncResult *result) { return func(result); }

	void SetQueueId(DWORD new_queue_id) { queue_id = new_queue_id; }
};

#define METHODASYNCCALLBACK(invoker, method)                                \
	AsyncCallbackInvoker invoker{std::bind(&AudioCaptureHelper::method, \
					       this, std::placeholders::_1)};

class AudioCaptureHelper {
private:
	CaptureOptions options;

	wil::com_ptr<IAudioClient> client;
	wil::com_ptr<IAudioCaptureClient> capture_client;

	wil::unique_cotaskmem_ptr<WAVEFORMATEX> format;

	wil::unique_event event_data;
	wil::unique_event event_data_forward;

	wil::unique_handle data_map;
	wil::unique_mapview_ptr<audio_capture_helper_data_t> data;

	DWORD queue_id;
	wil::com_ptr<IMFAsyncResult> packet_ready_result;
	MFWORKITEM_KEY packet_ready_key;

	AUDIOCLIENT_ACTIVATION_PARAMS GetParams();
	PROPVARIANT GetPropvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params);

	void InitFormat();
	void InitClient();

	void InitCapture();
	void InitData();

	HRESULT OnPacketReady(IMFAsyncResult *result);
	bool Tick(int event_id);

public:
	AudioCaptureHelper(CaptureOptions options) : options{options}
	{
		InitCapture();
		InitData();
	};

	~AudioCaptureHelper() { MFUnlockWorkQueue(queue_id); };

	METHODASYNCCALLBACK(callback_packet_ready, OnPacketReady);

	void Start();
	void Stop();
};
