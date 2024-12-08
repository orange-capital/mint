defmodule Mint.Proxy.Socks5 do
  @moduledoc false
  alias Mint.Negotiate

  @spec connect(tuple(), tuple()) :: {:ok, Mint.HTTP.t()} | {:error, term()}
  def connect(proxy, host) do
    case establish_proxy(proxy, host) do
      {:ok, socket} ->
        upgrade_connection(socket, host)
      {:error, reason} ->
        {:error, reason}
    end
  end

  def upgrade_connection(socket, {scheme, host, port, opts}) do
    case Negotiate.upgrade(:socks5, socket, scheme, host, port, opts) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} ->
        %Mint.HTTPError{module: __MODULE__, reason: {:proxy, reason}}
    end
  end

  def establish_proxy({proxy_host, proxy_port, proxy_opts}, {_scheme, host, port, _opts}) do
    base_opts = [:binary, {:active, false}, {:packet, 0}, {:keepalive,  true}, {:nodelay, true}]
    accept_keys = [:linger, :nodelay, :send_timeout, :send_timeout_close, :raw, :inet6, :ip]
    transport_opts = Keyword.get(proxy_opts, :transport_opts, [])
    timeout = Keyword.get(transport_opts, :timeout, 20_000)
    connect_opts = filter_options(transport_opts, accept_keys, base_opts)
    ts_start = System.system_time(:millisecond)
    case :gen_tcp.connect(fmt_connect_host(proxy_host), proxy_port, connect_opts, timeout) do
      {:ok, socket} ->
        ts_end = System.system_time(:millisecond)
        remain_timeout = max(100, timeout - (ts_end - ts_start))
        case do_handshake(socket, host, port, proxy_opts, remain_timeout) do
          :ok ->
            {:ok, socket}
          {:error, reason} ->
            :gen_tcp.close(socket)
            {:error, reason}
        end
      {:error, reason} ->
        {:error, reason}
    end
  end

  def do_authentication(socket, user, pass, timeout) do
    ts_start = System.system_time(:millisecond)
    auth_req = Mint.Socks5.mk_auth()
    :ok = :gen_tcp.send(socket, auth_req)
    case recv_msg(socket, Mint.Socks5.recv_size(:auth_resp), timeout, "") do
      %{cmd: :auth_resp, method: 0} ->
        :ok
      %{cmd: :auth_resp, method: 2} ->
        :ok = :gen_tcp.send(socket, Mint.Socks5.mk_auth_data(user, pass))
        ts_end = System.system_time(:millisecond)
        remain_timeout = max(100, timeout - (ts_end - ts_start))
        case recv_msg(socket, Mint.Socks5.recv_size(:auth_status), remain_timeout, "") do
          %{cmd: :auth_status, status: 0} ->
            :ok
          %{cmd: :auth_status, status: status} ->
            {:error, {:proxy_error, status}}
          {:error, reason} ->
            {:error, reason}
        end
      %{} = other ->
        {:error, {:proxy_error, other}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  def do_connection(socket, host, port, proxy_opts, timeout) do
    resolve = Keyword.get(proxy_opts, :resolve, :remote)
    case resolve_addr(host, resolve) do
      {:error, reason} ->
        {:error, reason}
      addr ->
        connect = Mint.Socks5.mk_connect(addr, port)
        :ok = :gen_tcp.send(socket, connect)
        case recv_msg(socket, Mint.Socks5.recv_size(:reply), timeout, "") do
          %{cmd: :reply} ->
            :ok
          %{} = other ->
            {:error, {:proxy_error, other}}
          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp do_handshake(socket, host, port, proxy_opts, timeout) do
    case Keyword.get(proxy_opts, :proxy_auth) do
      nil ->
        ts_start = System.system_time(:millisecond)
        auth_req = Mint.Socks5.mk_auth(:noauth)
        :ok = :gen_tcp.send(socket, auth_req)
        case recv_msg(socket, Mint.Socks5.recv_size(:auth_resp), timeout, "") do
          %{cmd: :auth_resp, method: 0} ->
            ts_end = System.system_time(:millisecond)
            remain_timeout = max(100, timeout - (ts_end - ts_start))
            do_connection(socket, host, port, proxy_opts, remain_timeout)
          %{} = other ->
            {:error, {:proxy_error, other}}
          {:error, reason} ->
            {:error, reason}
        end
      {user, pass} ->
        ts_start = System.system_time(:millisecond)
        case do_authentication(socket, user, pass, timeout) do
          :ok ->
            ts_end = System.system_time(:millisecond)
            remain_timeout = max(100, timeout - (ts_end - ts_start))
            do_connection(socket, host, port, proxy_opts, remain_timeout)
          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp recv_msg(socket, length, timeout, buf) do
    case :gen_tcp.recv(socket, length, timeout) do
      {:ok, new_bin} ->
        new_buf = buf <> new_bin
        case Mint.Socks5.decode_c(new_buf) do
          {:more, more_len} ->
            recv_msg(socket, more_len, timeout, new_buf)
          msg ->
            msg
        end
    end
  end

  defp fmt_connect_host(ip_or_host) do
    cond do
      is_tuple(ip_or_host) -> ip_or_host
      is_binary(ip_or_host) -> to_charlist(ip_or_host)
      true -> ip_or_host
    end
  end

  defp filter_options(opts, accept_keys, acc) do
    acc_map = opts_to_map(acc)
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
    map_to_opts(acc2)
  end

  defp opts_to_map(opts) do
    Enum.reduce(opts, %{}, fn x, acc ->
      case x do
        {:raw, v1, v2, v3} -> Map.put(acc, :raw, {v1, v2, v3})
        {k, v} -> Map.put(acc, k, v)
        _ when is_atom(x) -> Map.put(acc, x, nil)
      end
    end)
  end

  defp map_to_opts(opts) do
    Enum.reduce(opts, [], fn x, acc ->
      case x do
        {:raw, {v1, v2, v3}} -> [{:raw, v1, v2, v3}| acc]
        {k, nil} -> [k| acc]
        {k, v} -> [{k, v}| acc]
      end
    end)
  end

  def resolve_addr(host, resolve) do
    case :inet.parse_address(host) do
      {:ok, {ip1, ip2, ip3, ip4}} ->
        {ip1, ip2, ip3, ip4}
      {:ok, {ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8}} ->
        {ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8}
      {:error, _} ->
        case resolve do
          :local ->
            case resolve_ip4(host) do
              {:error, _reason} -> resolve_ip6(host)
              ip -> ip
            end
          :local4 ->
            resolve_ip4(host)
          :local6 ->
            resolve_ip6(host)
          _ ->
            :erlang.iolist_to_binary(host)
        end
    end
  end

  defp resolve_ip6(host) do
    case :inet.getaddr(host, :inet6) do
      {:ok, {ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8}} ->
        {ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp resolve_ip4(host) do
    case :inet.getaddr(host, :inet) do
      {:ok, {ip1, ip2, ip3, ip4}} ->
        {ip1, ip2, ip3, ip4}
      {:error, reason} ->
        {:error, reason}
    end
  end

end
