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
    base_opts = [{:mode, :binary}, {:active, false}, {:packet, 0}, {:keepalive,  true}, {:nodelay, true}]
    accept_keys = [:mode, :active, :packet, :raw, :ip, :reuseaddr, :nodelay, :linger, :send_timeout, :send_timeout_close, :sndbuf]
    transport_opts = Keyword.get(proxy_opts, :transport_opts, [])
    timeout = Keyword.get(transport_opts, :timeout, 20_000)
    inet6? = Keyword.get(transport_opts, :inet6, false)
    connect_opts = Mint.Core.Util.filter_inet_opts(transport_opts, accept_keys, base_opts)
    connect_opts = if inet6?, do: [:inet6| connect_opts], else: connect_opts
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
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fmt_connect_host(ip_or_host) do
    cond do
      is_tuple(ip_or_host) -> ip_or_host
      is_binary(ip_or_host) -> to_charlist(ip_or_host)
      true -> ip_or_host
    end
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
