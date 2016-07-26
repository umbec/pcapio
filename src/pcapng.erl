%%%-------------------------------------------------------------------
%%% @author Umberto Corponi
%%% @copyright (C) 2016, Umberto Corponi
%%% @doc
%%%
%%% @end
%%% Created : 26. Jul 2016 14.09
%%%-------------------------------------------------------------------

-module(pcapng).

-export([decode/1]).

-include("../include/pcapng.hrl").
-include("pcapio_internal.hrl").


decode(Bin) when is_binary(Bin) ->
  case endian(Bin) of
    error ->
      erlang:error(?INVALID_MAGIC);
    Endian ->
      Dblocks = [ decode_block(Endian, B) ||
        B <- split_blocks(Endian, Bin, [])],
      {ok, Dblocks}
  end;
decode(_) ->
  erlang:error(badarg).


decode_block(_Endian, Block) when byte_size(Block) < 12 ->
	erlang:error(?INVALID_BLOCK_LEN);
decode_block(Endian, Block) ->
  if
    Endian =:= big ->
      <<Type:32/big, TotLen:32/big, Rest/binary>> = Block,
      <<EndTotLen:32/big>> = erlang:binary_part(Rest, {byte_size(Rest), -4});
    Endian =:= little ->
      <<Type:32/little, TotLen:32/little, Rest/binary>> = Block,
      <<EndTotLen:32/little>> = erlang:binary_part(Rest, {byte_size(Rest), -4})
  end,
  TotLen /= EndTotLen andalso erlang:error(?INVALID_BLOCK_LEN),
	Body = erlang:binary_part(Rest, {0, byte_size(Rest)-4}),
  decode_block_body(Endian, Type, TotLen, Body).

%% ---------------------------------------------------------------------------------------------------------------------
%% ---------------------------------------------------------------------------------------------------------------------
%% ---------------------------------------------------------------------------------------------------------------------

decode_block_body(Endian, ?SHB_TYPE, Len, Body) ->
  %% 4.1. Section Header Block
  if
    Endian =:= big ->
      <<Magic:32/big, MajVer:16/big, MinVer:16/big, SecLen:64/big, Options/binary>> = Body;
    Endian =:= little ->
      <<Magic:32/little, MajVer:16/little, MinVer:16/little, SecLen:64/little, Options/binary>> = Body
  end,
	#pcapng_shb{
    magic_number = Magic,
    total_len = Len,
    version_major = MajVer,
    version_minor = MinVer,
    section_len = SecLen,
    options = Options
  };

decode_block_body(Endian, ?IDB_TYPE, Len, Body) ->
  %% 4.2. Interface Description Block
  if
    Endian =:= big ->
      <<LinkType:16/big, _Reserved:16/big, Snaplen:32/big, Options/binary>> = Body;
    Endian =:= little ->
      <<LinkType:16/little, _Reserved:16/little, Snaplen:32/little, Options/binary>> = Body
  end,
  #pcapng_idb{
    total_len = Len,
    link_type = LinkType,
    snaplen = Snaplen,
    options = Options
  };

decode_block_body(Endian, ?EPB_TYPE, Len, Body) ->
  %% 4.3. Enhanced Packet Block
  if
    Endian =:= big ->
      <<InterfaceId:32/big, TsHigh:32/big, TsLow:32/big,
        CapLen:32/big, OrigLen:32/big, Rest/binary>> = Body;
    Endian =:= little ->
      <<InterfaceId:32/little, TsHigh:32/little, TsLow:32/little,
        CapLen:32/little, OrigLen:32/little, Rest/binary>> = Body
  end,
  Data = erlang:binary_part(Rest, {0, OrigLen}),
  DataPaddedLen =  OrigLen + (4 - (OrigLen rem 4)) rem 4,
  Options = erlang:binary_part(Rest, {DataPaddedLen, byte_size(Rest)-DataPaddedLen}),
	#pcapng_epb{
    total_len = Len,
    interface_id = InterfaceId,
    timestamp_h = TsHigh,
    timestamp_l = TsLow,
    captured_len = CapLen,
    original_len = OrigLen,
    data = Data,
    options = Options
  };

decode_block_body(Endian, ?SPB_TYPE, Len, Body) ->
  %% 4.4. Simple Packet Block
  if
    Endian =:= big ->
      <<OrigLen:32/big, Rest/binary>> = Body;
    Endian =:= little ->
      <<OrigLen:32/little, Rest/binary>> = Body
  end,
  Data = erlang:binary_part(Rest, {0, OrigLen}),
  #pcapng_spb{
    total_len = Len,
    original_len = OrigLen,
    data = Data
  };

decode_block_body(_Endian, ?NRB_TYPE, Len, _Body) ->
  %% 4.5. Name Resolution Block
  #pcapng_nrb{
    total_len = Len,
    records = [todo],
    options = [todo]
  };

decode_block_body(Endian, ?ISB_TYPE, Len, Body) ->
  %% 4.6. Interface Statistics Block
  if
    Endian =:= big ->
      <<InterfaceId:32/big, TsHigh:32/big, TsLow:32/big, Options/binary>> = Body;
    Endian =:= little ->
      <<InterfaceId:32/little, TsHigh:32/little, TsLow:32/little, Options/binary>> = Body
  end,
  #pcapng_isb{
    total_len = Len,                        %% u32 total lenght (block included)
    interface_id = InterfaceId,
    timestamp_h = TsHigh,
    timestamp_l = TsLow,
    options = Options
  };

decode_block_body(Endian, Type, Len, Body)
  when Type == ?CB_TYPE orelse Type == ?CB_TYPE_NOCOPY ->
  %% 4.7. Custom Block
  if
    Endian =:= big ->
      <<EnterpriseNumber:32/big, Rest/binary>> = Body;
    Endian =:= little ->
      <<EnterpriseNumber:32/little, Rest/binary>> = Body
  end,
	#pcapng_cb{
    type = Type,
    total_len = Len,
    enterprise_number = EnterpriseNumber,
    data = Rest,
    options = []
  };

decode_block_body(_Endian, _Type, _Len, _Body) ->
	erlang:error(unsupported_block_type).

%% ---------------------------------------------------------------------------------------------------------------------
%% ---------------------------------------------------------------------------------------------------------------------
%% ---------------------------------------------------------------------------------------------------------------------

endian(<<_Type:32, _Len:32, ?PCAPNG_MAGIC_NUM:32/big, _/binary>>) ->
  big;
endian(<<_Type:32, _Len:32, ?PCAPNG_MAGIC_NUM:32/little, _/binary>>) ->
  little;
endian(<<_Type:32, _Len:32, _:32/little, _/binary>>) ->
  error.

%% ---------------------------------------------------------------------------------------------------------------------

split_blocks(_Endian, <<>>, Blocks) ->
  lists:reverse(Blocks);

split_blocks(big, <<_:32, TotLen:32/big, _/binary>> = Bin, Blocks) ->
  Block = erlang:binary_part(Bin, {0, TotLen}),
  Rest = erlang:binary_part(Bin, {TotLen, byte_size(Bin)-TotLen}),
  split_blocks(big, Rest, [Block|Blocks]);

split_blocks(little, <<_:32, TotLen:32/little, _/binary>> = Bin, Blocks) ->
  Block = erlang:binary_part(Bin, {0, TotLen}),
  Rest = erlang:binary_part(Bin, {TotLen, byte_size(Bin)-TotLen}),
  split_blocks(little, Rest, [Block|Blocks]);

split_blocks(_, _, _) ->
  erlang:error(invalid_block).
