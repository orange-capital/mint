defmodule Mint.Socks5 do
  @moduledoc """
    - pack/unpack socks5 command
  """
  @version 0x05
  @rsv 0x00
  @frag 0x00
  @ipv4 0x01
  @ipv6 0x04
  @domain 0x03

  @cmd_connect 0x01
  @cmd_udp_associate  0x03

  @auth_ver 0x01

  def recv_size(:connect), do: 4
  def recv_size(:auth), do: 3
  def recv_size(:auth_data), do: 3
  def recv_size(:reply), do: 5
  def recv_size(:auth_status), do: 2
  def recv_size(:auth_resp), do: 2

  def mk_auth(code \\ :username) do
    code_int = auth_to_int(code)
    <<@version, 1, code_int>>
  end

  def mk_auth_data(user, pass) do
    ul = byte_size(user)
    pl = byte_size(pass)
    <<1, ul, user :: binary, pl, pass :: binary>>
  end

  def mk_connect(addr, port) do
    addr_bin = encode_addr_data({addr, port})
    <<@version, 1, 0, addr_bin :: binary>>
  end

  def mk_reply(code \\ :success) do
    code_int = errorcode_to_int(code)
    <<@version, code_int, @rsv, @ipv4, 0::32, 0::16>>
  end

  def mk_auth_reply(code \\ :success) do
    code_int = errorcode_to_int(code)
    <<@auth_ver, code_int>>
  end

  def mk_udp_reply(code, addr \\ {0, 0, 0, 0}, port \\ 0) do
    addr_bin = encode_addr_data({addr, port})
    code_int = errorcode_to_int(code)
    <<@version, code_int, @rsv>> <> addr_bin
  end
  # client msg
  def decode_c(<<@version, method>>) do
    %{cmd: :auth_resp, method: method}
  end
  def decode_c(<<@auth_ver, status>>) do
    %{cmd: :auth_status, status: status}
  end
  def decode_c(<<@version, rep, rev, a_type, addr_bin :: binary>>) do
    decode_addr_data(a_type, addr_bin, %{cmd: :reply, reply: rep, reserve: rev})
  end
  def decode_c(bin) do
    {:error, {:invalid_msg, bin}}
  end

  # server msg
  def decode_s(<<@version, n, methods::binary-size(n)>>) do
    %{cmd: :auth_method, method: :erlang.binary_to_list(methods)}
  end
  def decode_s(<<@version, @cmd_connect, @rsv, type, rest::binary>>) do
    decode_addr_data(type, rest, %{cmd: :connect})
  end
  def decode_s(<<@version, @cmd_udp_associate, @rsv, type, rest::binary>>) do
    decode_addr_data(type, rest, %{cmd: :udp_associate})
  end
  def decode_s(<<@auth_ver, u_len, user::binary-size(u_len), p_len, password::binary-size(p_len)>>) do
    %{cmd: :auth, user: user, password: password}
  end
  def decode_s(<<@version, rest::binary>>) when byte_size(rest) < 512, do: :more
  def decode_s(<<@auth_ver, rest::binary>>) when byte_size(rest) < 512, do: :more
  def decode_s(bin) do
    {:error, {:invalid_msg, bin}}
  end

  def decode_addr_data(@ipv4, <<address::binary-size(4), port::16>>, msg) do
    addr = List.to_tuple(:erlang.binary_to_list(address))
    Map.merge(msg, %{addr: addr, port: port})
  end
  def decode_addr_data(@ipv4, bin, _msg), do: {:more, 6 - byte_size(bin)}
  def decode_addr_data(@ipv6, <<address::binary-size(16), port::16>>, msg) do
    addr = List.to_tuple(for <<a::16 <- address>>, do: a)
    Map.merge(msg, %{addr: addr, port: port})
  end
  def decode_addr_data(@ipv6, bin, _msg), do: {:more, 18 - byte_size(bin)}
  def decode_addr_data(@domain, <<len, domain::binary - size(len), port::16>>, msg) do
    Map.merge(msg, %{addr: to_charlist(domain), port: port})
  end
  def decode_addr_data(@domain, <<len, bin :: binary>>, _msg), do: {:more, len - byte_size(bin)}

  def decode_addr_data(_, _, _), do: {:error, :invalid_data}

  def encode_addr_data({{ip1, ip2, ip3, ip4}, port}) do
    <<@ipv4, ip1, ip2, ip3, ip4, port::16>>
  end
  def encode_addr_data({{ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8}, port}) do
    <<@ipv6, ip1::16, ip2::16, ip3::16, ip4::16, ip5::16, ip6::16, ip7::16, ip8::16, port::16>>
  end
  def encode_addr_data({host, port}) do
    host_bin = :erlang.iolist_to_binary(host)
    sz = byte_size(host_bin)
    <<@domain, sz, host_bin::binary, port::16>>
  end

  def decode_udp_data(<<@rsv::16, @frag, @ipv4, ip1, ip2, ip3, ip4, port::16, remain::binary>>) do
    {:ok, {{ip1, ip2, ip3, ip4}, port}, remain}
  end
  def decode_udp_data(<<@rsv::16, @frag, @ipv6, ip1::16, ip2::16, ip3::16, ip4::16, ip5::16, ip6::16, ip7::16, ip8::16, port::16, remain::binary>>) do
    {:ok, {{ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8}, port}, remain}
  end
  def decode_udp_data(<<@rsv::16, @frag, @domain, len, domain::binary-size(len), port::16, remain::binary>>) do
    target = {:erlang.binary_to_list(domain), port}
    {:ok, target, remain}
  end
  def decode_udp_data(bin) do
    {:error, bin}
  end

  def encode_udp_data(target, payload) do
    bin = encode_addr_data(target)
    <<@rsv::16, @frag, bin :: binary, payload::binary>>
  end

  def errorcode_to_int(:success), do: 0x0
  def errorcode_to_int(:server_error), do: 0x1
  def errorcode_to_int(:not_allowed), do: 0x2
  def errorcode_to_int(:net_unreachable), do: 0x3
  def errorcode_to_int(:host_unreachable), do: 0x4
  def errorcode_to_int(:conn_refused), do: 0x5
  def errorcode_to_int(:ttl_expires), do: 0x6
  def errorcode_to_int(:cmd_notsupported), do: 0x7
  def errorcode_to_int(:atyp_nosupported), do: 0x8
  def errorcode_to_int(:undef), do: 0xff

  def auth_to_int(:noauth), do: 0x00
  def auth_to_int(:username), do: 0x02

end
