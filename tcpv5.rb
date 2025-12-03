class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  SSH_FINGERPRINTS = [
    { regex: /ubuntu|debian|centos|rhel|redhat/i, os: 'Linux', accuracy: 95 },
    { regex: /windows|win32|win64/i, os: 'Windows', accuracy: 90 },
    { regex: /freebsd|openbsd|netbsd/i, os: 'BSD', accuracy: 85 }
  ].freeze

  def initialize
    super(
      'Name' => 'Reliable TCP Scanner with OS & Web Detection',
      'Description' => %q{
        Simple and reliable scanner that detects open ports, OS via SSH, and web servers.
        Fixed socket handling issues for stable operation.
      },
      'Author' => [ 'NHAT', 'PHUOC' ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('PORTS', [true, "Ports to scan", "21,22,23,25,80,443,3389"]),
      OptInt.new('TIMEOUT', [true, "Socket timeout (ms)", 1000]),
      OptInt.new('CONCURRENCY', [true, "Concurrent ports", 5]),
      OptBool.new('OS_DETECTION', [true, "Enable SSH OS detection", true]),
      OptBool.new('WEB_DETECTION', [true, "Enable web server detection", true])
    ])

    deregister_options('RPORT')
  end

  def run_host(ip)
    timeout = datastore['TIMEOUT'].to_i / 1000.0
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    concurrency = datastore['CONCURRENCY'].to_i
    open_ports = []

    print_status("#{ip} - Scanning ports: #{datastore['PORTS']}")
    
    ports.each_slice(concurrency) do |port_chunk|
      threads = []
      
      port_chunk.each do |port|
        threads << framework.threads.spawn("Scan-#{ip}:#{port}", false) do
          begin
            s = connect(false, {
              'RPORT' => port,
              'RHOST' => ip,
              'ConnectTimeout' => timeout
            })
            
            open_ports << port
            print_good("#{ip}:#{port} - OPEN")
            # ghi nhận dữ liệu vào hệ thống metasploit
            report_service(
              host: ip,
              port: port,
              proto: 'tcp',
              state: 'open'
            )
          # cổng bị đóng
          rescue ::Rex::ConnectionRefused
            vprint_status("#{ip}:#{port} - closed")
          # không phản hồi (không biết rõ là mở hay đóng)
          rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
            vprint_status("#{ip}:#{port} - no response") if datastore['VERBOSE']
          # lớp bảo vệ giúp đóng chương trình, đảm bảo các vấn đề rò rỉ.
          ensure
            disconnect(s) if s && !s.closed?
          end
        end
      end

      threads.each(&:join)
      threads.each { |t| t.kill rescue nil }
    end

    # Phát hiện OS qua SSH
    if open_ports.include?(22) && datastore['OS_DETECTION']
      detect_os_via_ssh(ip, timeout)
    end

    # Phát hiện Web Server
    web_ports = [80, 443] & open_ports
    web_ports.each { |port| detect_web_server(ip, port) } if web_ports.any? && datastore['WEB_DETECTION']
  end

  def detect_os_via_ssh(ip, timeout)
    s = nil
    begin
      s = connect(false, {
        'RPORT' => 22,
        'RHOST' => ip,
        'ConnectTimeout' => [timeout * 2, 10].min
      })
      
      banner = s.get_once(1024, timeout) || ''
      return if banner.empty?
      
      SSH_FINGERPRINTS.each do |fp|
        if banner =~ fp[:regex]
          print_good("#{ip} - OS Detected: #{fp[:os]} (#{fp[:accuracy]}% accuracy)")
          
          report_note(
            host: ip,
            type: 'host.os',
            data: {
                os: fp[:os],
                method: 'ssh_banner'
            }
          )
          
          return
        end
      end
      
      print_status("#{ip} - Unknown OS from SSH banner")
    rescue => e
      vprint_error("#{ip} - SSH error: #{e.message}")
    ensure
      disconnect(s) if s && !s.closed?
    end
  end

  def detect_web_server(ip, port)
    require 'socket'
    require 'timeout'
    
    s = nil
    begin
      # Tạo socket trước khi vào timeout block
      s = TCPSocket.new(ip, port)
      
      Timeout.timeout(datastore['TIMEOUT'].to_i / 500) do
        s.write("GET / HTTP/1.1\r\nHost: #{ip}\r\nConnection: close\r\n\r\n")
        
        response = ''
        begin
          loop do
            data = s.readpartial(1024)
            response << data
            break if response.include?("\r\n\r\n") || response.length > 4096
          end
        rescue EOFError, Errno::ECONNRESET
          # Connection closed by server - vẫn xử lý response có sẵn
        end
        
        if response =~ /Server:\s*([^\r\n]+)/i
          server_banner = $1.strip
          server_info = parse_web_banner(server_banner)
          
          print_good("#{ip}:#{port} - Web Server: #{server_info[:name]} #{server_info[:version]}")
          
          report_service(
            host: ip,
            port: port,
            name: (port == 443 ? 'https' : 'http'),
            info: "Server: #{server_info[:name]} #{server_info[:version]}"
          )
          report_note(
            host: ip,
            port: port,
            type: 'web.server',
            data: {
                server: server_info[:name],
                version: server_info[:version],
                banner: server_banner
            }
          )
          
        else
          vprint_status("#{ip}:#{port} - No Server header found")
        end
      end
    rescue Timeout::Error
      vprint_error("#{ip}:#{port} - Web detection timed out")
    rescue => e
      vprint_error("#{ip}:#{port} - Web detection failed: #{e.class} #{e.message}")
    ensure
      # Đảm bảo đóng socket an toàn
      begin
        s.shutdown(2) if s && !s.closed?
      rescue
        # Bỏ qua lỗi khi shutdown
      end
      s.close if s && !s.closed?
    end
  end

  def parse_web_banner(banner)
    case banner.downcase
    when /apache/i
      { name: 'Apache', version: extract_version(banner, /apache[\/ ]?([\d.]+)/i) }
    when /nginx/i
      { name: 'Nginx', version: extract_version(banner, /nginx[\/ ]?([\d.]+)/i) }
    when /iis|internet information/i
      { name: 'Microsoft IIS', version: extract_version(banner, /iis[\/ ]?([\d.]+)/i) }
    when /lighttpd/i
      { name: 'Lighttpd', version: extract_version(banner, /lighttpd[\/ ]?([\d.]+)/i) }
    else
      { name: 'Unknown', version: 'N/A' }
    end
  end

  def extract_version(banner, pattern)
    match = banner.match(pattern)
    match ? match[1] : 'Unknown'
  end
end