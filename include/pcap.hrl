
-ifndef(pcap_hrl).
-define(pcap_hrl, true).

%% ============================================================================
%% PCAP traditional file format
%% [https://wiki.wireshark.org/Development/LibpcapFileFormat]
%% ============================================================================

-define(PCAP_MAGIC_NUM, 16#a1b2c3d4).

%% Global Header --------------------------------------------------------------

-define(PCAP_GH_SIZE, 24).

-record(pcap_gh, {                        %% Global Header
          magic_number = ?PCAP_MAGIC_NUM, %% u32 magic number
          version_major = 2,              %% u16 major version number
          version_minor = 4,              %% u16 minor version number
          thiszone,                       %% i32 GMT to local correction
          sigfigs = 0,                    %% u32 accuracy of timestamps
          snaplen,                        %% u32 max length of captured packets, in octets
          network                         %% u32 data link type
         }).

%% Packet Header --------------------------------------------------------------

-define(PCAP_PH_SIZE, 16).

-record(pcap_ph, {        %% Packet Header
        ts_sec,           %% u32 timestamp seconds
        ts_usec,          %% u32 timestamp microseconds
        incl_len,         %% u32 number of octets of packet saved in file
        orig_len,         %% u32 actual length of packet
        data              %% Packet payload
       }).

%% ============================================================================

-endif.