-module(pcapng).

-export([decode/1]).

-include("../include/pcapng.hrl").

decode(Bin) when is_binary(Bin) ->
	<<Type:32/native, _Len:32, Magic:32/native, _/binary>> = Bin,
	case {Type, Magic} of
	{?SHB_TYPE, ?PCAPNG_MAGIC_NUM} ->
		Blocks = split_blocks(Bin, []),
		DecBlocks = decode_blocks(Blocks, []),
		{ok, DecBlocks};
	{?SHB_TYPE, _} ->
		erlang:error(invalid_magic_number);
	_ ->
		erlang:error(invalid_file_format)
	end.

split_blocks(<<>>, Blocks) ->
	lists:reverse(Blocks);
split_blocks(<<_:32, TotLen:32/native, _/binary>> = Bin, Blocks) ->
	Block = erlang:binary_part(Bin, {0, TotLen}),
	Rest = erlang:binary_part(Bin, {TotLen, byte_size(Bin)-TotLen}),
	split_blocks(Rest, [Block|Blocks]);
split_blocks(_, _) ->
	erlang:error(invalid_block).

decode_blocks([], DecBlocks) ->
	lists:reverse(DecBlocks);
decode_blocks([Block | _T], _DecBlocks) when byte_size(Block) < 12 ->
	erlang:error(insufficient_block_len);
decode_blocks([Block | T], DecBlocks) ->
	<<Type:32/native, TotLen:32/native, Rest/binary>> = Block,
	<<EndTotLen:32/native>> = erlang:binary_part(Rest, {byte_size(Rest), -4}),
	Body = erlang:binary_part(Rest, {0, byte_size(Rest)-4}),
	case TotLen == EndTotLen of
		true ->
			DecBlock = decode_block(Type, TotLen, Body),
			decode_blocks(T, [DecBlock|DecBlocks]);
		false ->
			erlang:error(invalid_block_total_len)
	end.


decode_block(?SHB_TYPE, _Len, _Body) ->
	#pcapng_shb{};
decode_block(?IDB_TYPE, _Len, _Body) ->
	#pcapng_idb{};
decode_block(?SPB_TYPE, _Len, _Body) ->
	#pcapng_spb{};
decode_block(?NRB_TYPE, _Len, _Body) ->
	#pcapng_nrb{};
decode_block(?ISB_TYPE, _Len, _Body) ->
	#pcapng_isb{};
decode_block(?EPB_TYPE, _Len, _Body) ->
	#pcapng_epb{};
decode_block(Type, _Len, _Body)
  when Type == ?CB_TYPE orelse Type == ?CB_TYPE_NOCOPY ->
	#pcapng_cb{};
decode_block(_, _Len, _Body) ->
	erlang:error(unsupported_block_type).

