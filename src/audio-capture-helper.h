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

#include "common.h"

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
	wil::unique_event &shutdown_event;

	ULONG refcount = 0;

	AsyncCallbackInvoker(func_type func, wil::unique_event &shutdown_event)
		: func{func}, shutdown_event{shutdown_event}
	{
	}

	STDMETHOD_(ULONG, AddRef)() { return ++refcount; }
	STDMETHOD_(ULONG, Release)()
	{
		--refcount;

		if (refcount == 0)
			shutdown_event.SetEvent();

		return refcount;
	}

	STDMETHOD(GetParameters)(DWORD *flags, DWORD *queue)
	{
		*flags = 0;
		*queue = queue_id;
		return S_OK;
	}

	STDMETHOD(Invoke)(IMFAsyncResult *result) { return func(result); }

	void SetQueueId(DWORD new_queue_id) { queue_id = new_queue_id; }
};

#define METHODASYNCCALLBACK(invoker, method, shutdown_event)                 \
	AsyncCallbackInvoker invoker{std::bind(&AudioCaptureHelper::method,  \
					       this, std::placeholders::_1), \
				     shutdown_event};

namespace wil {
using unique_mfshutdown_call =
	wil::unique_call<decltype(&::MFShutdown), ::MFShutdown>;

_Check_return_ inline unique_mfshutdown_call MFStartup(DWORD flags = 0)
{
	::MFStartup(MF_VERSION, flags);
	return unique_mfshutdown_call();
}
}

class AudioCaptureHelper {
private:
	DWORD pid;
	bool include_tree;

	obs_source_t *source;

	wil::unique_couninitialize_call couninit{wil::CoInitializeEx()};
	wil::unique_mfshutdown_call mfshutdown{wil::MFStartup(MFSTARTUP_LITE)};

	wil::com_ptr<IAudioClient> client;
	wil::com_ptr<IAudioCaptureClient> capture_client;

	wil::unique_cotaskmem_ptr<WAVEFORMATEX> format;

	wil::unique_event event_data;
	wil::unique_event event_result_shutdown;

	DWORD queue_id;
	wil::com_ptr<IMFAsyncResult> packet_ready_result;
	MFWORKITEM_KEY packet_ready_key;

	AUDIOCLIENT_ACTIVATION_PARAMS GetParams();
	PROPVARIANT GetPropvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params);

	void InitFormat();
	void InitClient();

	void InitCapture();

	HRESULT OnPacketReady(IMFAsyncResult *result);

public:
	AudioCaptureHelper(obs_source_t *source, DWORD pid, bool include_tree);
	~AudioCaptureHelper();

	METHODASYNCCALLBACK(callback_packet_ready, OnPacketReady,
			    event_result_shutdown);
};
