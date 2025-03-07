defmodule Mint.Core.Util do
  @moduledoc false

  alias Mint.Types

  @spec hostname(keyword(), String.t()) :: String.t()
  def hostname(opts, address) when is_list(opts) do
    case Keyword.fetch(opts, :hostname) do
      {:ok, hostname} ->
        hostname

      :error when is_binary(address) ->
        address

      :error ->
        raise ArgumentError, "the :hostname option is required when address is not a binary"
    end
  end

  @spec inet_opts(:gen_tcp | :ssl, :gen_tcp.socket() | :ssl.sslsocket()) :: :ok | {:error, term()}
  def inet_opts(transport, socket) do
    with {:ok, opts} <- transport.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- transport.setopts(socket, buffer: buffer) do
      :ok
    end
  end

  @spec scheme_to_transport(atom()) :: module()
  def scheme_to_transport(:http), do: Mint.Core.Transport.TCP
  def scheme_to_transport(:https), do: Mint.Core.Transport.SSL
  def scheme_to_transport(module) when is_atom(module), do: module

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end

  # Adds a header to the list of headers unless it's nil or it's already there.
  @spec put_new_header(Types.headers(), String.t(), String.t() | nil) :: Types.headers()
  def put_new_header(headers, name, value)

  def put_new_header(headers, _name, nil) do
    headers
  end

  def put_new_header(headers, name, value) do
    if List.keymember?(headers, name, 0) do
      headers
    else
      [{name, value} | headers]
    end
  end

  @spec put_new_header_lazy(Types.headers(), String.t(), (-> String.t())) :: Types.headers()
  def put_new_header_lazy(headers, name, fun) do
    if List.keymember?(headers, name, 0) do
      headers
    else
      [{name, fun.()} | headers]
    end
  end

  # If the buffer is empty, reusing the incoming data saves
  # a potentially large allocation of memory.
  # This should be fixed in a subsequent OTP release.
  @spec maybe_concat(binary(), binary()) :: binary()
  def maybe_concat(<<>>, data), do: data
  def maybe_concat(buffer, data) when is_binary(buffer), do: buffer <> data

  def filter_inet_opts(opts, accept_keys, acc) do
    acc_map = inet_opts_to_map(acc)
    acc2 = Enum.reduce(opts, acc_map, fn x, acc1 ->
      case x do
        {:raw, v1, v2, v3} ->
          if :raw in accept_keys, do: Map.put(acc1, :raw, {v1, v2, v3}), else: acc1
        {k, v} ->
          if k in accept_keys, do: Map.put(acc1, k, v), else: acc1
        _ ->
          if x in accept_keys, do: Map.put(acc1, x, nil), else: acc1
      end
    end)
    map_to_inet_opts(acc2)
  end

  defp inet_opts_to_map(opts) do
    Enum.reduce(opts, %{}, fn x, acc ->
      case x do
        {:raw, v1, v2, v3} -> Map.put(acc, :raw, {v1, v2, v3})
        {k, v} -> Map.put(acc, k, v)
        _ when is_atom(x) -> Map.put(acc, x, nil)
      end
    end)
  end

  defp map_to_inet_opts(opts) do
    Enum.reduce(opts, [], fn x, acc ->
      case x do
        {:raw, {v1, v2, v3}} -> [{:raw, v1, v2, v3}| acc]
        {k, nil} -> [k| acc]
        {k, v} -> [{k, v}| acc]
      end
    end)
  end
end
