%%%-------------------------------------------------------------------
%%% @author Umberto Corponi
%%% @copyright (C) 2016, Umberto Corponi
%%% @doc
%%%
%%% @end
%%% Created : 26. Jul 2016 14.09
%%%-------------------------------------------------------------------
-module(pcapio).
-author("Umberto Corponi").

-include("pcapio_internal.hrl").
-include("../include/pcap.hrl").
-include("../include/pcapng.hrl").

%% API
-export([file_format/1,
         decode/1]).

%%%-------------------------------------------------------------------

file_format(Bin) when not is_binary(Bin) ->
  {error, badarg};
file_format(<<?PCAP_MAGIC_NUM:32/big, _/binary>>) ->
  {pcap, big};
file_format(<<?PCAP_MAGIC_NUM:32/little, _/binary>>) ->
  {pcap, little};
file_format(<<_:32, _:32, ?PCAPNG_MAGIC_NUM:32/big, _/binary>>) ->
  {pcapng, big};
file_format(<<_:32, _:32, ?PCAPNG_MAGIC_NUM:32/little, _/binary>>) ->
  {pcapng, little};
file_format(_) ->
  {error, ?INVALID_FILE}.

%%%-------------------------------------------------------------------

decode(Bin) when not is_binary(Bin) ->
  {error, badarg};
decode(Bin) ->
  case file_format(Bin) of
    {error, Reason} -> {error, Reason};
    {pcap, _Endian} -> pcap:decode(Bin);
    {pcapng, _Endian} -> pcapng:decode(Bin)
  end.

