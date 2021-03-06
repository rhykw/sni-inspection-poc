require 'socket'

gs = TCPServer.open('', 443)
addr = gs.addr
addr.shift
printf("server is on %s\n", addr.join(':'))

header_struct = [
  { label: 'Handshake Type', length: 1, lenbytes: 0 },
  { label: 'Length', length: 3, lenbytes: 0 },
  { label: 'Version', length: 2, lenbytes: 0 },
  { label: 'Timestamp', length: 4, lenbytes: 0 },
  { label: 'Random', length: 28, lenbytes: 0 },
  { label: 'Session ID', length: 0, lenbytes: 1 },
  { label: 'Cipher Suites', length: 0, lenbytes: 2 },
  { label: 'Compression Methods', length: 0, lenbytes: 1 },
  { label: 'Extensions', length: 0, lenbytes: 2 }

]

while true
  Thread.start(gs.accept) do |s|       # save to dynamic variable
    print(s, " is accepted\n")

    buf = ''
    s.readpartial(65_540, buf)
    payload_length = buf.bytes[3] * 256 + buf.bytes[4]
    tls_payload = buf.bytes[5..nil].map { |b| b.chr }.join

    puts "Handshake Type:#{tls_payload[0].unpack('H2')}"
    puts "        Length:#{format('%02x%02x%02x', tls_payload[1].bytes.first, tls_payload[2].bytes.first,
                                  tls_payload[3].bytes.first)}"
    puts '       Version:'
    tls_payload[4...6].each_byte { |i| printf('%02x', i) }
    puts ''
    puts tls_payload[6...10].unpack('H8')
    puts tls_payload[10...38].unpack('H56')

    # puts tls_payload[0...7].unpack('H12')
    # puts tls_payload[6...37].unpack('H130')
    puts tls_payload[38...511].unpack('H*')
    p tls_payload[38..nil]

    pn = 0
    extensions_bytes = []
    target_servername = ''
    header_struct.each do |s|
      printf s[:label]
      lb = s[:length]

      unless s[:length] > 0
        lb = tls_payload.bytes[pn...pn + s[:lenbytes]].map { |i| format('%02x', i) }.join.hex
        printf '(%d %s)', lb, tls_payload.bytes[pn...pn + s[:lenbytes]].map { |i| format('%02x', i) }.join
        pn += s[:lenbytes]
      end
      printf '[%d...%d] %d: ', pn, pn + lb, lb

      tls_payload.bytes[pn...pn + lb].each { |i| printf(' %02x', i) }
      extensions_bytes = tls_payload.bytes[pn...pn + lb] if s[:label] == 'Extensions'
      pn += lb
      printf "\n"
    end

    pn = 0
    while pn < extensions_bytes.count
      b = extensions_bytes[pn...nil]
      extension_type = b[0] * 256 + b[1]
      extension_data_len = b[2] * 256 + b[3]
      extension_data = b[4...4 + extension_data_len]
      printf "- extension_type=%5d extension_data_len=%5d extension_data=%s\n",
             extension_type,
             extension_data_len,
             extension_data.map { |i|
               format('%02x', i)
             }.join
      pn += 4 + extension_data_len
      puts "    (pn=#{pn})"

      next unless extension_type == 0

      # data = 000e00000b6578616d706c652e636f6d
      list_len = extension_data[0] * 256 + extension_data[1]
      sn_type  = extension_data[2]
      sn_len   = extension_data[3] * 256 + extension_data[4]
      name     = extension_data[5...5 + sn_len]
      printf "  SNI: Server Name Type:(%d) Name: %s\n", sn_type, name.pack('C*')
      target_servername = name.pack('C*')
    end

    unless target_servername.empty?
      TCPSocket.open(target_servername, 443) do |rs|
        p rs
        p s
        rs.write buf
        loop do
          $stdout.write 'x'
          begin
            data_to_send = s.read_nonblock(1024)
            $stdout.write ">(#{data_to_send.length})"
            rs.write(data_to_send)
          rescue IO::WaitReadable, IO::WaitWritable
          end

          begin
            data_received = rs.read_nonblock(1024)
            $stdout.write "<(#{data_received.length})"
            z = s.write data_received
            $stdout.write "z=#{z} "
            # $stdout.write "ready  break" if rs.nil? || rs.closed? || rs.eof?
            # break  if rs.nil? || rs.closed? || rs.eof?
            $stdout.write 'now here'
          rescue IO::WaitReadable
            puts 'WaitReadable'
            IO.select([rs, s])
          rescue IO::WaitWritable
            puts 'WaitWritable'
            IO.select([], [s, rs])
          end
        end
        $stdout.write 'break loop'
      end
    end

    print(s, " is gone\n")
    s.close
  end
end
