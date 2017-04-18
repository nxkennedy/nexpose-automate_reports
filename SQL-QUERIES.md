
# Nexpose SQL Queries

Collection of helpful Nexpose SQL queries that can be used to extract tailored reports
from Nexpose.

# Table of Contents

* [Hosts Running a Specific OS](#Hosts-Running-a-Specific-OS)
* [Software Installed on Assets](#Software-Installed-on-Assets)
* [Vulnerable Assets in a Site](#Vulnerable-Assets-in-a-Site)
* [Assets Affected by a Specific Vulnerability](#Assets-Affected-by-a-Specific-Vulnerability)
* [Assets Affected by Multiple Specific Vulnerabilities](#Assets-Affected-by-Multiple-Specific-Vulnerabilities)
* [Assets Running OpenSSL](#Assets-Running-OpenSSL)
* [Identify SSL/TLS Versions Detected During Scan](#Identify-SSL/TLS-Versions-Detected-During-Scan)
* [Discovery Details (Heavy)](#Discovery-Details-Heavy)
* [Discovery Details (Lite)](#Discovery-Details-Lite)
* [Vulnerability Instances](#Vulnerability-Instances)

# <a name="Hosts-Running-a-Specific-OS"></a>Hosts Running a Specific OS
```sql

SELECT dsi.name AS "Site Name", da.ip_address AS "IP Address", da.host_name AS "Host Name", 
dos.description AS "Operating System", dht.description AS "Host Type" 
FROM dim_asset da
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_host_type dht USING (host_type_id)
JOIN dim_site_asset dsa USING (asset_id)
JOIN dim_site dsi USING (site_id)
WHERE dos.description like '%Linux%'
ORDER BY dos.description

```
# <a name="Software-Installed-on-Assets"></a>Software Installed on Assets
```sql

SELECT dsi.name AS "Site Name", da.ip_address AS "IP Address", da.host_name AS "Host Name", 
dos.description AS "Operating System", dht.description AS "Host Type", 
ds.vendor AS "Software Vendor", ds.name AS "Software Name", ds.version AS "Software Version"
FROM dim_asset da
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_host_type dht USING (host_type_id)
JOIN dim_asset_software das USING (asset_id)
JOIN dim_software ds USING (software_id)
JOIN dim_site_asset dsa USING (asset_id)
JOIN dim_site dsi USING (site_id)
ORDER BY da.ip_address, ds.vendor, ds.name

```
# <a name="Vulnerable-Assets-in-a-Site"></a>Vulnerable Assets in a Site
```sql

SELECT dsi.name AS "Site Name", da.ip_address AS "IP Address", da.host_name AS "Host Name", 
dos.description AS "Operating System", dht.description AS "Host Type", 
ds.vendor AS "Software Vendor", ds.name AS "Software Name", ds.version AS "Software Version"
FROM dim_asset da
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_host_type dht USING (host_type_id)
JOIN dim_asset_software das USING (asset_id)
JOIN dim_software ds USING (software_id)
JOIN dim_site_asset dsa USING (asset_id)
JOIN dim_site dsi USING (site_id)
ORDER BY da.ip_address, ds.vendor, ds.name

```
# <a name="Assets-Affected-by-a-Specific-Vulnerability"></a>Assets Affected by a Specific Vulnerability
```sql

SELECT da.host_name, da.ip_address, dv.title
FROM fact_asset_vulnerability_finding favf
JOIN dim_asset da using (asset_id)
JOIN dim_vulnerability dv using (vulnerability_id)
WHERE dv.title = 'Red Hat: CVE-2016-5195 (Dirty COW): Important: kernel security and enhancement update (RHSA-2016:2128 (Multiple Advisories))'
ORDER BY host_name

```
# <a name="Assets-Affected-by-Multiple-Specific-Vulnerabilities"></a>Assets Affected by Multiple Specific Vulnerabilities
```sql

SELECT da.host_name, da.ip_address, da.mac_address, dv.title
FROM fact_asset_vulnerability_finding favf
JOIN dim_asset da using (asset_id)
JOIN dim_vulnerability dv using (vulnerability_id)
WHERE dv.title = 'Red Hat: CVE-2016-5195 (Dirty COW): Important: kernel security and enhancement update (RHSA-2016:2128 (Multiple Advisories))'
OR dv.title = 'Amazon Linux AMI: CVE-2016-5195 (Dirty COW): Security patch for kernel (ALAS-2016-757)'
OR dv.title = 'Debian: DSA-3696 (CVE-2016-5195) (Dirty COW): linux -- security update'
OR dv.title = 'Ubuntu: USN-3107-2 (Multiple Advisories) (CVE-2016-5195) (Dirty COW): Linux kernel (Raspberry Pi 2) vulnerability'
OR dv.title = 'Cent OS: CVE-2016-5195 (Dirty COW): CESA-2016:2098 (kernel))'
OR dv.title = 'Oracle Linux: CVE-2016-5195 (Dirty COW): ELSA-2016-2124-1 - kernel security and bug fix update'
ORDER BY host_name

```
# <a name="Assets-Running-OpenSSL"></a>Assets Running OpenSSL
```sql

SELECT da.ip_address as "Device IP", da.host_name as "Host Name", dsf.vendor as "OS Type", 
dos.description AS "OS Version", dht.description as "Platform", dsf.name AS "Software", 
dsf.version as "Version", to_char(fa.scan_finished, 'yyyy-mm-dd HH12:MI AM') as "Last Scan Date" 
FROM fact_asset fa
JOIN dim_asset da USING (asset_id) 
JOIN dim_asset_software dss USING (asset_id) 
JOIN dim_operating_system dos USING (operating_system_id) 
JOIN dim_host_type dht USING (host_type_id) 
JOIN dim_site_asset dsa USING (asset_id) 
JOIN dim_software dsf USING (software_id) WHERE dsf.name like '%openssl%’

```
# <a name="Identify-SSL/TLS-Versions-Detected-During-Scan"></a>Identify SSL/TLS Versions Detected During Scan
```sql

SELECT da.ip_address, da.host_name, dos.description, dt.tag_name, dv.title, favf.proof, ds.summary
FROM fact_asset_vulnerability_instance favf
JOIN dim_vulnerability dv ON dv.vulnerability_id = favf.vulnerability_id
JOIN dim_asset da ON da.asset_id = favf.asset_id
JOIN dim_operating_system dos ON dos.operating_system_id = da.operating_system_id
LEFT OUTER JOIN dim_tag_asset dta ON dta.asset_id = favf.asset_id
LEFT OUTER JOIN dim_tag dt ON dt.tag_id = dta.tag_id
JOIN dim_vulnerability_solution vs ON vs.vulnerability_id = favf.vulnerability_id
JOIN dim_solution ds ON ds.solution_id = vs.solution_id
WHERE dv.title like '%TLS/SSL Server Supports SSL %'
ORDER BY dv.title ASC

```
# <a name="Discovery-Details-Heavy"></a>Discovery Details (Heavy)
```sql

WITH open_ports AS ( 
      SELECT asset_id, array_to_string(array_agg(dp.name || '/' || port ORDER BY port), ',') AS ports 
      FROM dim_asset_service 
        JOIN dim_protocol dp USING (protocol_id) 
      GROUP BY asset_id 
        ) 
SELECT da.ip_address AS "IP Address", host_name AS "Asset Host Name", dos.description AS "OS Details", 
ports AS "Open Ports", first_discovered AS "Asset First Discovered Date", last_discovered AS "Asset Last Discovered Date", 
sites AS "Site Name(s)"  
FROM fact_asset_discovery  
JOIN dim_asset da USING (asset_id)  
JOIN dim_operating_system dos USING (operating_system_id) 
JOIN open_ports USING (asset_id)

```
# <a name="Discovery-Details-Lite"></a>Discovery Details (Lite)
```sql

SELECT mac_address AS "MAC", da.ip_address AS "IP", host_name AS "Host Name", d$
FROM fact_asset_discovery
  JOIN dim_asset da USING (asset_id)
  JOIN dim_operating_system dos USING (operating_system_id)
  JOIN dim_host_type dht USING (host_type_id)

```
# <a name="Vulnerability-Instances"></a>Vulnerability Instances
```sql

SELECT da.ip_address as "IP Address", da.host_name as "Name", dv.title as "Title", dv.date_published as "Published",
dv.severity as "Severity", fv.affected_assets as "Assets", fv.vulnerability_instances as "Instances",
fv.affected_sites as "Sites"
FROM fact_vulnerability as fv
LEFT OUTER JOIN fact_asset_vulnerability_instance as favi ON favi.vulnerability_id = fv.vulnerability_id
LEFT OUTER JOIN fact_asset as fa ON fa.asset_id = favi.asset_id
LEFT OUTER JOIN dim_asset as da ON da.asset_id = fa.asset_id
LEFT OUTER JOIN dim_vulnerability as dv ON dv.vulnerability_id = fv.vulnerability_id
WHERE dv.title like '%Default or Guessable SNMP community names: public%'

```
