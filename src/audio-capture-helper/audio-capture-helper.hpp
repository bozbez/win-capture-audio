#include <stdio.h>

#include <windows.h>
#include <audioclient.h>
#include <audioclientactivationparams.h>

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

class AudioCaptureHelper {
private:
	CaptureOptions options;

	wil::com_ptr<IAudioClient> client;
	wil::com_ptr<IAudioCaptureClient> capture_client;

	wil::unique_cotaskmem_ptr<WAVEFORMATEX> format;

	wil::unique_event event_data;
	wil::unique_event events[NUM_HELPER_EVENTS_TOTAL];

	wil::unique_handle data_map;
	wil::unique_mapview_ptr<audio_capture_helper_data_t> data;

	AUDIOCLIENT_ACTIVATION_PARAMS get_params();
	PROPVARIANT get_propvariant(AUDIOCLIENT_ACTIVATION_PARAMS *params);

	void init_format();
	void init_client();

	void init_capture();

	void init_data();
	void init_events();

	void forward_audio_packet();
	bool tick(int event_id);

public:
	AudioCaptureHelper(CaptureOptions options) : options{options} {
		init_capture();

		init_data();
		init_events();
	};

	~AudioCaptureHelper() = default;

	void run();
};
