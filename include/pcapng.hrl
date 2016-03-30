
%% ============================================================================
%% PCAPNG file format 
%% [http://www.tcpdump.org/pcap/pcap.html]
%% ============================================================================

-define(PCAPNG_MAGIC_NUM, 16#1A2B3C4D).

%% Section Header Block -------------------------------------------------------

-define(SHB_TYPE, 16#0A0D0D0A).                  %% Section Header Block Type
-define(SHB_UNDEF_SEC_LEN, 16#FFFFFFFFFFFFFFFF). %% Length of section is undefined

-record(pcapng_shb, {
		total_len,                        %% u32 total lenght (block included)
		magic_number = ?PCAPNG_MAGIC_NUM, %% u32 magic number
        version_major = 1,                %% u16 major version number
        version_minor = 0,                %% u16 minor version number
		section_len = ?SHB_UNDEF_SEC_LEN,
		options = []
	}).

%% Interface Description Block ------------------------------------------------

-define(IDB_TYPE, 16#1).              %% Interface Description Block

-record(pcapng_idb, {
	total_len,                        %% u32 total lenght (block included)
    link_type = 1,                    %% u16 link toe
	snaplen,
	options = []
}).

%% Enhanced Pachet Block ------------------------------------------------------

-define(EPB_TYPE, 16#6).              %% Enhanced Packet Block

-record(pcapng_epb, {
	total_len,                        %% u32 total lenght (block included)
    interface_id,
	timestamp_h,
	timestamp_l,
	captured_len,
	original_len,
	data,
	options = []
}).

%% Simple Packet Block --------------------------------------------------------

-define(SPB_TYPE, 16#3).              %% Simple Packet Block

-record(pcapng_spb, {
	total_len,                        %% u32 total lenght (block included)
	original_len,
	data
}).

%% Name Resolution Block ------------------------------------------------------

-define(NRB_TYPE, 16#4).              %% Name Resolution Block

-record(pcapng_nrb, {
	total_len,                        %% u32 total lenght (block included)
	records = [],
	options = []
}).

%% Interface Statistics Block -------------------------------------------------

-define(ISB_TYPE, 16#5).              %% Interface Statistics Block

-record(pcapng_isb, {
	total_len,                        %% u32 total lenght (block included)
    interface_id,
	timestamp_h,
	timestamp_l,
	options = []
}).

%% Custom Block ---------------------------------------------------------------

-define(CB_TYPE, 16#BAD).              %% Custom Block
-define(CB_TYPE_NOCOPY, 16#40000BAD).  %% Custom Block

-record(pcapng_cb, {
	type = ?CB_TYPE, 
	total_len,                        %% u32 total lenght (block included)
    enterprise_number,
	data,
	options = []
}).

