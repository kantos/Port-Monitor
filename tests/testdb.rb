
require 'nmap/program'
require 'nmap/xml'
gem 'dbd-mysql'
require 'mysql'
require 'dbi'



begin
     # connect to the MySQL server
     dbh = DBI.connect("DBI:Mysql:port_monitor:localhost", 
                      "root", "password")
     # get server version string and display it
     row = dbh.select_one("SELECT VERSION()")
     puts "Server version: " + row[0]
rescue DBI::DatabaseError => e
     puts "An error occurred"
     puts "Error code:    #{e.err}"
     puts "Error message: #{e.errstr}"
ensure
     # disconnect from server
     dbh.disconnect if dbh
end
