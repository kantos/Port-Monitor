# Port-Monitor
Tools to keep continuous monitoring of a pool of IP open ports

This code was ran with Ruby 2.1.2 at Ubuntu 14.04

The Library for using nmap is:
https://github.com/sophsec/ruby-nmap

These are the required dependencies
sudo apt-get install mysql-server mysql-client
sudo apt-get install libmysqlclient-dev
sudo apt-get install nmap
sudo apt-get install zlib1g-dev

gem install rprogram
gem install nokogiri
gem install ruby-nmap
gem install dbi
gem install mysql
gem install dbd-mysql
gem install mandrill-api
gem install mail

After ruby is working, you must create a database with the file database.sql

Before running the script you need to configure:

1. the database name, IP (usually localhost), username, and password. Line
2. e-mail settings, "from@gmail.com" (Line 246).
3. if you want to send e-mails with mandrill you need to get an api-key and replace it where it says 'madrill-api-key' (Line 146)

You will also need to change parameters for e-mail

Someday I'll include a config file, in order to make this easier.

As nmap needs high privileges, you need to run the script with sudo.

chmod +x port_monitor.rb
sudo ./port_monitor.rb



Logs are rotated daily, but XML files will pile up with time.
log/activity.log - everything is logged
log/diff.log - just logs port status changes

In hosts.txt you can add new IPs, one IP per line. CIDR notation or any notation is not supported.
After a scan finishes, the script will process the hosts.txt file and rename it hosts.txt.processed.
