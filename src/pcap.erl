-module(pcap).

-export([decode/1,
         decode_blocks/1,
         decode_global_header/1,
         encode_header/1,
         decode_gh/1,
         decode_ph/1]).

-include("../include/pcap.hrl").

-spec decode(Bin) -> Resp when
   Bin  :: binary(),
   Resp :: {ok, {GlobalHeader, Rest}},
   GlobalHeader :: #pcap_gh{},
   Rest ::binary().
   
decode(Bin) when not is_binary(Bin) ->
  {error, param};
decode(Bin) when size(Bin) < ?PCAP_GH_SIZE ->
  {error, invalid_len};
decode(<<Magic:32/native-unsigned, 
         VM:16/native-unsigned-integer,
         Vm:16/native-unsigned-integer,
         _Rest/binary>> = Bin) ->
  case Magic of
  ?PCAP_MAGIC_NUM ->
    case {VM, Vm} of
    {2, 4} ->
      Ret = decode_global_header(Bin),
      {ok, Ret};
    {_,_} ->
      {error, unsupported_version}
    end;
  _ ->
    {error, invalid_magic_number}
  end.

decode_global_header(Bin) ->
  Gh = erlang:binary_part(Bin, {0, ?PCAP_GH_SIZE}),
  Rest = erlang:binary_part(Bin, {?PCAP_GH_SIZE, byte_size(Bin) - ?PCAP_GH_SIZE}),
  {decode_gh(Gh), Rest}.


decode_blocks(Bin) ->
  decode_blocks(Bin, []).

decode_blocks(<<>>, Blocks) ->
  lists:reverse(Blocks);
decode_blocks(Bin, Blocks) when byte_size(Bin) >= ?PCAP_PH_SIZE ->
  {ok, Dec, Rest} = decode_block(Bin),
  decode_blocks(Rest, [Dec | Blocks]);
decode_blocks(_, _) ->
  erlang:error(invalid_block).

decode_block(Bin) when byte_size(Bin) >= ?PCAP_PH_SIZE ->
  Ph = erlang:binary_part(Bin, {0, ?PCAP_PH_SIZE}),
  Dph = decode_ph(Ph),
  Plen = Dph#pcap_ph.incl_len,
  Payload = erlang:binary_part(Bin, {?PCAP_PH_SIZE, Plen}),
  BlockLen = ?PCAP_PH_SIZE + Plen,
  Rest = erlang:binary_part(Bin, {BlockLen, byte_size(Bin) - BlockLen}),
  {ok, Dph#pcap_ph{data = Payload}, Rest}.

encode_header(#pcap_gh{magic_number=Mn,
                     version_major=VM,
                     version_minor=Vm,
                     thiszone=Tz,
                     sigfigs=Sf,
                     snaplen=Sl,
                     network=Nw}) ->
  <<Mn:32/native-unsigned-integer,
    VM:16/native-unsigned-integer,
    Vm:16/native-unsigned-integer,
    Tz:32/native-signed-integer,
    Sf:32/native-unsigned-integer,
    Sl:32/native-unsigned-integer,
    Nw:32/native-unsigned-integer>>;

encode_header(#pcap_ph{ts_sec=Tss,
                     ts_usec=Tsu,
                     incl_len=Il,
                     orig_len=Ul}) ->
  <<Tss:32/native-unsigned-integer,
    Tsu:32/native-unsigned-integer,
    Il:32/native-unsigned-integer,
    Ul:32/native-unsigned-integer>>.

decode_gh(<<Mn:32/native-unsigned-integer,
      VM:16/native-unsigned-integer,
      Vm:16/native-unsigned-integer,
      Tz:32/native-signed-integer,
      Sf:32/native-unsigned-integer,
      Sl:32/native-unsigned-integer,
      Nw:32/native-unsigned-integer>>) ->
  #pcap_gh{magic_number=Mn,
           version_major=VM,
           version_minor=Vm,
           thiszone=Tz,
           sigfigs=Sf,
           snaplen=Sl,
           network=Nw};
decode_gh(_)->
  false.

decode_ph(<<Tss:32/native-unsigned-integer,
      Tsu:32/native-unsigned-integer,
      Il:32/native-unsigned-integer,
      Ul:32/native-unsigned-integer>>) ->
  #pcap_ph{ts_sec=Tss,
           ts_usec=Tsu,
           incl_len=Il,
           orig_len=Ul};
decode_ph(_)->
  false.

