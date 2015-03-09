

require 'nmap/program'
require 'nmap/xml'
require 'mail'
require 'mandrill'

gem 'dbd-mysql'
require 'mysql'
require 'dbi'
require 'logger'
require 'net/smtp'



$logger = Logger.new('log/activity.log', 'daily')
$logger.level = Logger::INFO

$loggerDiff = Logger.new('log/diff.log', 'daily')
$loggerDiff.level = Logger::INFO

def klog(message)
  $logger.info(message)
  puts "[#{Time.now}]  #{message}" 
end

def klogDiff(message)
  $loggerDiff.info(message)
  puts "[#{Time.now}]  #{message}" 
end

STDOUT.sync = true

def connect_db
  # connect to the MySQL server
  begin
    dbh = DBI.connect("DBI:Mysql:port_monitor:localhost","root", "password")
    
    # get server version string and display it
    row = dbh.select_one("SELECT VERSION()")
    klog "Server version: " + row[0]
    return dbh
  rescue DBI::DatabaseError => e
    klog "An error occurred"
    klog "Error code:    #{e.err}"
    klog "Error message: #{e.errstr}"
  ensure
  # disconnect from server
  #dbh.disconnect if dbh
  end
end

def disconnect_db(dbh)
  dbh.disconnect if dbh
end

def insert_intodb(scan_ip, scan_id)
  
  
  dbhe=connect_db()
  
  Nmap::XML.new("xml/nmap_scan_#{scan_id}_#{scan_ip}.xml") do |xml|
  #Nmap::XML.new('scan.xml') do |xml|
    
    
    dbhe['AutoCommit'] = false # Set auto commit to false.
    dbhe.transaction do |dbh|
    
      sth = dbh.prepare("INSERT INTO scans (start_date, end_date, scan_id) values (?,?,?)")
      #puts xml.scanner.start_time.to_s #its the scanner start_time, not the hosts
      #sth.execute(xml.scanner.start_time.to_s, scan_id)
      #scan_id = dbh.func(:insert_id)
      #sth.finish
   
      sthScan = dbh.prepare("INSERT INTO scan_results (scan_id, ip_text, ip, port, protocol_tcp, state, service, service_product, service_version, service_confidence) values (?,?,?,?,?,?,?,?,?,?)")
  
      sthScanned_ip = dbh.prepare("INSERT INTO scan_ips (scan_id,ip_text,os_match,os_class,open_ports_qty) values (?,?,?,?,?)")
  
      sthLast_scan = dbh.prepare("UPDATE ips SET  last_scan_date = ? where ip_text = ?")

      xml.each_host do |host| #it must be just one host
  
        klog "Nmap results for #{host.ip}, open ports: #{host.open_ports.count}"
        klog "Start date: #{host.start_time}, End date: #{host.end_time}"
 
        sth.execute(host.start_time.to_s, host.end_time.to_s, scan_id)
        sth.finish
  
       # if (host.os.nil?)
       #   host_os = nil
       # else
       #   host_os = host.os.matches.join(" | ").slice(0,499)
       # end
  
        sthScanned_ip.execute(scan_id, host.ip, (host.os.nil?)?nil:host.os.matches.join(" | ").slice(0,499), "", host.open_ports.count)
	sthLast_scan.execute(host.start_time.to_s, host.ip)
  
        host.each_port do |port|
          if (port.service.nil?)
             service_product = nil
             service_version = nil
             service_confidence = nil
          else
             service_product = port.service.product
             service_version = port.service.version
             service_confidence = port.service.confidence
          end

          klog "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}\t#{service_product}\t#{service_version}\t#{service_confidence}"
          sthScan.execute(scan_id, host.ip,0,port.number,port.protocol,port.state,port.service.to_s.slice(0,199),service_product.to_s.slice(0,199),service_version.to_s.slice(0,199),service_confidence)
        end
  
      end
  
      sthScan.finish
      sthScan = dbh.prepare("UPDATE port_monitor.scans SET status=1 WHERE scan_id=?") #flag scan as finished
      sthScan.execute(scan_id)
  
    end
  end
  dbhe['AutoCommit'] = true
  disconnect_db(dbhe)
  scan_id
end

def run_nmap(targets, scan_id)
  Nmap::Program.scan do |nmap|
  #nmap.sudo = true
    nmap.syn_scan = true
    nmap.service_scan = true
    nmap.os_fingerprint = true
    #nmap.xml = 'scan.xml'
    nmap.xml = "xml/nmap_scan_#{scan_id}_#{targets}.xml"
    nmap.verbose = true

    #nmap.ports = [20,21,22,23,25,80,110,443,512,522,8080,1080] #for testing purposes
    nmap.ports = ["1-65535"]
    nmap.targets = targets #accepts an array of IPs
    klog nmap.arguments
  end
end


def sendmail(subject,to,text,htmltext,attachment = nil)

        m = Mandrill::API.new 'madrill-api-key'
        message = {  
         :subject=> subject,  
         :from_name=> "Port Monitor Alert",  
         :text=>text,  
         :to=>[  
           {  
             :email=> to,  
           }  
         ],  
         :html=>htmltext,  
         :from_email=>"info@portmonitoralert.com"  
        }  
        sending = m.messages.send message  
        puts sending

end




def min(a,b)
  a < b ? a : b
end

def run_diff(target, scan_id)

  dbh=connect_db()
  sthLastScanExist = dbh.prepare("SELECT ip_text from port_monitor.scan_ips where ip_text=? limit 1")
  sthLastScanExist.execute(target)

  lastScanExist=sthLastScanExist.fetch_all
  count=lastScanExist.length
  sthLastScanExist.finish

  if (count == 0)
    klog "Previous scan of #{target} non existant"
  return 0
  end

  sthNewScan = dbh.prepare("SELECT ip_text, port, state from scan_results where scan_id=? and ip_text=? order by ip_text, port")
  sthNewScan.execute(scan_id, target)

  #sthLastScan = dbh.prepare("SELECT distinct scan_id from port_monitor.scan_ips where ip=? order by scan_id desc limit 2")

  sthLastScan = dbh.prepare("SELECT ip_text, port, state from port_monitor.scan_results where scan_id=(SELECT distinct scan_id from port_monitor.scan_ips where ip_text=? order by scan_id desc limit 1,1) and ip_text=? order by ip_text, port")
  sthLastScan.execute(target, target)

  # countLastPorts=sthLastScan.num_rows
  # countNewPorts=sthNewScan.num_rows

  lastScan=sthLastScan.fetch_all
  newScan=sthNewScan.fetch_all
  countLastPorts=lastScan.length
  countNewPorts=newScan.length
  sthLastScan.finish
  sthNewScan.finish
  msg=""
  #puts countNewPorts
  #puts countLastPorts

  sthDiff = dbh.prepare("INSERT INTO port_monitor.diff (ip, scan_id, port_changed, port_previous_state, port_new_state) VALUES (?, ?, ?, ?, ?)")

  changes=false
  iLast=0
  iNew=0
  while (iNew < countNewPorts && iLast < countLastPorts) do
    if lastScan[iLast][1]==newScan[iNew][1] # Same port
      if lastScan[iLast][2]!=newScan[iNew][2] #Different States
        msg+= "#{lastScan[iLast][0]}: Port #{lastScan[iLast][1]} changed from #{lastScan[iLast][2]} to #{newScan[iNew][2]}\n"
        klog  "#{lastScan[iLast][0]}: Port #{lastScan[iLast][1]} changed from #{lastScan[iLast][2]} to #{newScan[iNew][2]}"
        klogDiff "#{lastScan[iLast][0]}: Port #{lastScan[iLast][1]} changed from #{lastScan[iLast][2]} to #{newScan[iNew][2]}"
      sthDiff.execute(lastScan[iLast][0], scan_id, lastScan[iLast][1], lastScan[iLast][2], newScan[iNew][2])
      changes=true
      end
    iLast+=1
    iNew+=1
    elsif lastScan[iLast][1]>newScan[iNew][1]
      msg+= "#{lastScan[iLast][0]}: Port #{newScan[iNew][1]} changed from FILTERED to #{newScan[iNew][2]}\n"
      klog "#{lastScan[iLast][0]}: Port #{newScan[iNew][1]} changed from FILTERED to #{newScan[iNew][2]}"
      klogDiff "#{lastScan[iLast][0]}: Port #{newScan[iNew][1]} changed from FILTERED to #{newScan[iNew][2]}"
      sthDiff.execute(lastScan[iLast][0], scan_id, newScan[iNew][1], 'FILTERED', newScan[iNew][2])
    changes=true
    iNew+=1
    else
      msg+= "#{lastScan[iLast][0]}: Port #{lastScan[iLast][1]} changre from #{lastScan[iLast][2]} to FILTERED\n"
      klog "#{lastScan[iLast][0]}: Port #{lastScan[iLast][1]} changre from #{lastScan[iLast][2]} to FILTERED"
      klogDiff "#{lastScan[iLast][0]}: Port #{lastScan[iLast][1]} changre from #{lastScan[iLast][2]} to FILTERED"
      sthDiff.execute(lastScan[iLast][0], scan_id, lastScan[iLast][1], lastScan[iLast][2],'FILTERED')
    changes=true
    iLast+=1
    end
  end

  sthDiff.finish
  disconnect_db(dbh)
  
  if (!changes)
    klog "There are no changes"
  else
    sendmail("Port Monitor: Changes Detected","from@gmail.com",msg,"")
  end

end


def reset_scans()
  dbh=connect_db()
  count = dbh.do("UPDATE port_monitor.ips SET status=0")
  
  if (count == 0)
    klog "No hosts to scan"
    exit
  end
  disconnect_db(dbh)
end

#-1 nuevos
#0 no escaneados
#1 in process
#2 escaneaodos
def select_next_target()
  dbh=connect_db()
  #checking for new hosts
  sth = dbh.prepare("SELECT ip_text, status, id FROM port_monitor.ips where status<=0 order by status asc, id asc  limit 1")
  sth.execute()
  target=sth.fetch_all
  
  targetHost=target.length
  sth.finish
  disconnect_db(dbh)
  
  if (targetHost != 0)
    return target[0] 
  end
  
  #all hosts where scanned
  reset_scans()
  select_next_target() #loop prevented in reset_scans
  
end

def get_next_scan_id()
  dbh=connect_db()
  sth = dbh.prepare("SELECT scan_id FROM port_monitor.scans order by scan_id desc limit 1")
  res = sth.execute()
  target=sth.fetch_all
  hasResults = (target.length != 0)
  sth.finish
  
  disconnect_db(dbh)
    
  if (hasResults)
    return target[0][0]+1
  else
    return 1
  end
  
end


def update_scan_status(target, status)
  dbh=connect_db()
  sth = dbh.prepare("UPDATE port_monitor.ips SET status=? WHERE id=?")
  sth.execute(status, target[2])
  sth.finish
  disconnect_db(dbh)
end


#delete incomplete scans (marked with status 0) so diff is not performed with them
def verifiy_unfinished_scans()
  dbh=connect_db()
  sth = dbh.do("UPDATE port_monitor.ips SET status=-1 WHERE status=1")
  sth = dbh.do("DELETE FROM port_monitor.scans WHERE status=0")
  
  disconnect_db(dbh)
  #TODO: imprimir en el log que scans de que IP se eliminaron
  
end

def add_new_hosts()
 
 if !File.file?("hosts.txt")
   return
 end

 dbh=connect_db()
 klog "New hosts.txt file found"
 sth = dbh.prepare("INSERT INTO port_monitor.ips (ip_text, status) VALUES (?, -1)")
 
 added=0
 not_added=0
 File.open("hosts.txt").readlines.each do |line|
#   
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.match(line))
      line.delete!("\n\r")
      klog "Adding: "+ line
      begin
        sth.execute(line)
        klog "Added "+ line
        added+=1
      rescue Exception => e
        klog "The IP: #{line} was already in the database"
        not_added+=1
      end
    else 
      klog "This is not a valid IP: #{line}"
      not_added+=1
    end
 end
 klog "Added: #{added}, Not Added: #{not_added}"
 File.rename("hosts.txt", "hosts.txt.processed")

 disconnect_db(dbh)
end

begin
# connect to the MySQL server
  dbh=connect_db()

  verifiy_unfinished_scans()
  add_new_hosts()

  i=0
  while (i<1)

    target = select_next_target()
    scan_id = get_next_scan_id()
    #logger.info("Starting scan with scan_id: #{scan_id}")
    klog("Starting scan with scan_id: #{scan_id}")
    #puts "scan_id: #{scan_id}"

    ip = target[0]
    #logger.info("Target: #{ip}")
    klog("Target: #{ip}")
    #puts "target: #{target[0]} - version: #{target[1]}"
    
    update_scan_status(target, 1) #mark scan as in process
    
    klog "start nmap of: " + ip + " - version: #{target[1]}"
    run_nmap(ip, scan_id)
    klog "end nmap of: " + ip + " - version: #{target[1]}"

    
    insert_intodb(ip, scan_id)
    klog "scan results inserted into database"

    run_diff(ip, scan_id)
    #run_diff(dbh, '127.0.0.1', 73)
    update_scan_status(target, 2) #mark scan as finished
    

    #i+=1
  end

  klog "fin scan: " + scan_id.to_s

rescue DBI::DatabaseError => e
  klog "An error occurred"
  klog "Error code:    #{e.err}"
  klog "Error message: #{e.errstr}"
ensure
# disconnect from server
dbh.disconnect if dbh
end

