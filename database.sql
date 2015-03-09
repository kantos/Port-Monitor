CREATE DATABASE  IF NOT EXISTS `port_monitor` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `port_monitor`;
-- MySQL dump 10.13  Distrib 5.5.35, for debian-linux-gnu (i686)
--
-- Host: 127.0.0.1    Database: port_monitor
-- ------------------------------------------------------
-- Server version	5.5.35-0ubuntu0.13.10.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `diff`
--

DROP TABLE IF EXISTS `diff`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `diff` (
  `diff_id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(15) DEFAULT NULL,
  `scan_id` int(11) DEFAULT NULL,
  `port_changed` int(11) DEFAULT NULL,
  `port_previous_state` varchar(45) DEFAULT NULL,
  `port_new_state` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`diff_id`),
  KEY `fk_scan_id_idx` (`scan_id`),
  KEY `index_ip` (`ip`),
  CONSTRAINT `fk_scan_id` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ips`
--

DROP TABLE IF EXISTS `ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ips` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_text` varchar(15) NOT NULL,
  `last_scan_date` datetime DEFAULT NULL,
  `status` int(10) DEFAULT '-1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_text_UNIQUE` (`ip_text`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan_ips`
--

DROP TABLE IF EXISTS `scan_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scan_ips` (
  `scan_id` int(11) NOT NULL,
  `ip_text` varchar(15) DEFAULT NULL,
  `os_match` varchar(500) DEFAULT NULL,
  `os_class` varchar(500) DEFAULT NULL,
  `open_ports_qty` int(11) DEFAULT NULL,
  PRIMARY KEY (`scan_id`),
  KEY `scan_ip_index` (`ip_text`),
  CONSTRAINT `fk_scanned_ips_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan_results`
--

DROP TABLE IF EXISTS `scan_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scan_results` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) DEFAULT NULL,
  `ip_text` varchar(15) DEFAULT NULL,
  `ip` int(11) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  `protocol_tcp` varchar(3) DEFAULT NULL,
  `state` varchar(45) DEFAULT NULL,
  `service` varchar(200) DEFAULT NULL,
  `service_product` varchar(200) DEFAULT NULL,
  `service_version` varchar(200) DEFAULT NULL,
  `service_confidence` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index1` (`scan_id`),
  CONSTRAINT `fk_scan_results_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2837 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scans`
--

DROP TABLE IF EXISTS `scans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scans` (
  `scan_id` int(11) NOT NULL,
  `start_date` datetime DEFAULT NULL,
  `end_date` datetime DEFAULT NULL,
  `status` int(11) DEFAULT '0',
  PRIMARY KEY (`scan_id`),
  KEY `status_idx` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2014-11-18  2:12:03
