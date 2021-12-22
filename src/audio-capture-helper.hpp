#pragma once

#include <stdio.h>
#include <array>
#include <functional>
#include <thread>

#include <windows.h>

#include <audiopolicy.h>
#include <audioclient.h>
#include <audioclientactivationparams.h>
#include <mmdeviceapi.h>

#include <wrl/implements.h>
#include <wil/com.h>

#include "common.hpp"

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

namespace HelperEvents {
enum HelperEvents {
	PacketReady,
	Shutdown,
	Count,
};
};

class AudioCaptureHelper {
private:
	DWORD pid;
	bool include_tree;

	obs_source_t *source;
	wil::unique_couninitialize_call couninit{wil::CoInitializeEx()};

	wil::com_ptr<IAudioClient> client;
	wil::com_ptr<IAudioCaptureClient> capture_client;

	wil::unique_cotaskmem_ptr<WAVEFORMATEX> format;

	std::array<wil::unique_event, HelperEvents::Count> events;
	std::thread capture_thread;

	AUDIOCLIENT_ACTIVATION_PARAMS GetParams();
	PROPVARIANT GetPropvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params);

	void InitFormat();
	void InitClient();

	void InitCapture();

	void Capture();
	void ForwardPacket();

public:
	AudioCaptureHelper(obs_source_t *source, DWORD pid, bool include_tree);
	~AudioCaptureHelper();
};
