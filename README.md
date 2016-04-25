Splunk2Resilient
================

### Version 0.7.1

Splunk2Resilient is used to process Splunk alerts into Resilient tickets.

Installation
------

- Load files to your Splunks scripts directory /\<splunk installation\>/bin/scripts
- Make s2r.py executable:
```sh    
  chmod +x s2r.py
```
- Update s2r.conf settings based on your environment
- Test connectivity to your Resilient instance:
```sh
  s2r.py --testconnection
```
- Add s2r.py script to Splunk alerts under 'File name of shell scrip to run'

Command Options
------

Print command usage
```sh    
  s2r.py --help
```
Get count of items in processing queue
```sh    
  s2r.py --checkqueue
```
Process items in queue
```sh    
  s2r.py --processqueue
```
Test connection to Resilient
```sh    
  s2r.py --testconnection
```

Usage
------
Configure Splunk to call the s2r.py script when an alert triggers. Alert data is then processed and sent to the Resilient API.  
Queries can have any number of focus, artifact, or both fields in a query.

##### o_\<field\>
- Fields with the o_ prefix are called focus fields.  
Processed events are grouped into tickets based on unique field values. 
As an example all o_ipaddress values would be grouped together under a single ticket. If we had 30 events in an alert, and 15 of those 30 events had the same o_ipaddress value and the remainder were unique o_ipaddress values, you would have 16 tickets.  15 unique and 1 with a common o_ipaddress value. 

##### a_\<field\>
- Fields with the a_ prefix are called artifact fields.  
Processed events with fields with a prefix of a_ are parsed into artifacts which are inserted into Resilient. 
As an exmpale all a_ipaddress values would be detected as a type IP, and inserted into the created Resilient ticket.
Splunk2Resilient parser attempts to detect which kind of artifact the field contains automatically.  If its unable to do so, it defaults to a type of string.
- Artifact types detected:
 * IP
 * DNS
 * URL
 * EMAIL
 * MD5
 * SHA1
 * STRING

##### oa_\<field\>
- Fields with the oa_ prefix are a mix of focus and artifact fields.
Processed events are grouped into unique tickets based on field values. They are also inserted into created tickets as artifacts.

##### Ticket priority
If indicated in the Splunk event title, a Resilient ticket priority can be automaticly set.

Valid options include: 
- CRITICAL
- HIGH
- MEDIUM
- LOW
- TEST

In order to parse the priority from the event title, titles should be formated as such:
- [\<event name\> \<priority\>] \<brief description\> 



Recovery
------
In case of loss of connectivity to the Resilient ticketing system, if set to do so, the script can store events as json files in a queue.  When the system becomes available, and a new Splunk event triggers, the script will attempt to insert any queued events.  
Configure recovery behavior under [recovery] section in the s2r.conf file.

You may also elect to recieve emails of failed events during a connectivity issue with Resilient.

You can check the number of items in the queue by executing:
```sh    
   /<splunk installation>/bin/scripts/s2r.py --checkqueue
```
You can attempt to send stored events by executing: 
```sh
    /<splunk installation>/bin/scripts/s2r.py --processqueue
```
