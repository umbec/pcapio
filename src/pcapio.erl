%%%-------------------------------------------------------------------
%%% @author Umberto Corponi
%%% @copyright (C) 2016, <COMPANY>
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
-export([decode/1]).

decode(<<?PCAP_MAGIC_NUM:32/big, _/binary>> = Bin) when is_binary(Bin) ->
  pcap:decode(Bin);
decode(<<?PCAP_MAGIC_NUM:32/little, _/binary>> = Bin) when is_binary(Bin) ->
  pcap:decode(Bin);
decode(<<_:32, _:32, ?PCAPNG_MAGIC_NUM:32/big, _/binary>> = Bin) when is_binary(Bin) ->
  pcapng:decode(Bin);
decode(<<_:32, _:32, ?PCAPNG_MAGIC_NUM:32/little, _/binary>> = Bin) when is_binary(Bin) ->
  pcapng:decode(Bin);
decode(<<_:32, _:32, ?PCAPNG_MAGIC_NUM:32/little, _/binary>> = Bin) when is_binary(Bin) ->
  {error, ?INVALID_FILE}.


