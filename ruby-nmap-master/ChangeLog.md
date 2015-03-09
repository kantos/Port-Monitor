### 0.6.0 / 2012-11-07

* Added {Nmap::Service}.
* Renamed `Nmap::IpidSequence` to {Nmap::IpIdSequence}.
* Renamed {Nmap::Host#ipidsequence} to {Nmap::Host#ip_id_sequence}.
* Renamed {Nmap::Host#tcpsequence} to {Nmap::Host#tcp_sequence}.
* Renamed {Nmap::Host#tcptssequence} to {Nmap::Host#tcp_ts_sequence}.

### 0.5.1 / 2012-05-27

* Replaced ore-tasks with
  [rubygems-tasks](https://github.com/postmodern/rubygems-tasks#readme).

### 0.5.0 / 2011-04-11

* Require nokogiri ~> 1.3.
* Require rprogram ~> 0.3.
* `ip_scan` in {Nmap::Task} should map to `-sO` (thanks corvus).

### 0.4.1 / 2010-11-23

* Fixed a bug in {Nmap::XML#each} where it was calling `each_up_hosts`,
  and not {Nmap::XML#each_up_host}.
* {Nmap::OS#each_class}, {Nmap::OS#each_match}, {Nmap::XML#each_host} and
  {Nmap::XML#each_up_host} now return an Enumerator object if no block
  is given.
* Use `yield` instead of `block.call` for a slight performance improvement.

### 0.4.0 / 2010-11-17

* Added new options to {Nmap::Task} based on nmap 5.21:
  * `-PY` - `nmap.sctp_init_ping`
  * `-PR` - `nmap.arp_ping`
  * `-sY` - `nmap.sctp_init_scan`
  * `-sZ` - `nmap.sctp_cookie_echo_scan`
  * `--allports` - `nmap.all_ports`
  * `-sR` - `nmap.rpc_scan`
  * `-T` - `nmap.timing_template`
  * `-T0` - `nmap.paranoid_timing`
  * `-T1` - `nmap.sneaky_timing`
  * `-T2` - `nmap.polite_timing`
  * `-T3` - `nmap.normal_timing`
  * `-T4` - `nmap.aggressive_timing`
  * `-T5` - `nmap.insane_timing`
  * `--randomize-hosts` - `nmap.randomize_hosts`
  * `--adler32` - `nmap.sctp_adler32`
  * `-oA` - `nmap.output_all`
  * `-d` - `nmap.debug`
  * `--stats-every` - `nmap.stats_every`
  * `--release-memory` - `nmap.release_memory`
* Specify that ruby-nmap requires `nmap` >= 5.00.

### 0.3.0 / 2010-11-08

* Added {Nmap::Host#scripts}.
* Added {Nmap::Port#scripts}.

### 0.2.0 / 2010-10-29

* Require nokogiri >= 1.3.0.
* Require rprogram ~> 0.2.0.
* Added {Nmap::XML#tasks}.
* Added {Nmap::Scanner#start_time}.
* Added {Nmap::ScanTask#duration}.
* Added {Nmap::Host#start_time}.
* Added {Nmap::Host#end_time}.
* Allow `Nmap::Tasks#ports=` to accept port ranges.
* Omit the `-p` option if no ports are given to {Nmap::Task}.
* Have the `Nmap::Host#each_*` methods return an `Enumerator` object if no
  block is given.

### 0.1.1 / 2010-01-02

* Require RProgram >= 0.1.8.
  * Adds `sudo` and `sudo=` instance methods to {Nmap::Task}.

### 0.1.0 / 2009-11-13

* Initial release.
  * Provides a Ruby interface for running Nmap.
  * Provides a Parser for enumerating Nmap XML scan files.

