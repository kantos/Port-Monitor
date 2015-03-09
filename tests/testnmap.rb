
require 'nmap/program'
require 'nmap/xml'
gem 'dbd-mysql'
require 'mysql'
require 'dbi'


begin 
  Nmap::XML.new("delete.xml") do |xml|
  #Nmap::XML.new('scan.xml') do |xml|

    puts xml.scanner.start_time.to_s

    #puts xml.class.methods
    xml.each_host do |host|
      puts "Nmap results for #{host.ip}, open ports: #{host.open_ports.count} #{host.start_time} #{host.end_time} #{host.os.matches.join(" | ")} | #{host.os.classes.length}"


      host.each_port do |port|
        puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service.to_s.slice(0,199)}\t#{port.service.product.to_s.slice(0,199)}\t#{port.service.version.to_s.slice(0,199)}\t#{port.service.confidence}"
      end
    end
  end
end

