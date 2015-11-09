Splunk2Resilient v0.5
Used to process Splunk alerts into Resilient ticket items.

Installation:
	1.	Ensure Python2.7 is installed on the system, /usr/bin/env python should start python2.7
	2.	Load files to your Splunks scripts directory /<splunk installation>/bin/scripts
	3.	Make s2r.py executable:
		chmod +x s2r.py
	4.	Update s2r.conf settings with an editor
	5.	Test connectivity to your Resilient instance:
		./s2r.py --test-connection
	6.	Add script s2r.py as an option to any alert in Splunk you want tickets auto created on execution.


Command Options:
	./s2r.py --help
	./s2r.py --check-queue
	./s2r.py --process-queue
	./s2r.py --test-connection
	Script must be executed as the Splunk user, in the /<splunk installation>/bin/scripts directory


Normal usage:
	Configure Splunk to call this script when an alert triggers. Alert data is then processed and sent to Resilient.
	Splunk queries with special column names are treated differently:

		"o_<example>"
			Names that start with "o_" are used as a focus, and collections are formed based on these.
			1 ticket per collection of entries.

		"a_<example>"
			Names that start with "a_" are used to indicate these items are artifacts.

	More Examples:
		Example:	o_hostname  a_src_ip	a_filehash	somefield
		Example:	oa_emailaddress a_src_ip	a_filehash somefield
		* You can only have one focus column per alert query, otherwise the focus is dropped and each line will be treated as its own event.

	Ticket priority:
		If indicated in Alert Title ex: [ALERT-NAME-HERE HIGH], will take priority and set ticket
		Defaults to LOW, or whats configured in s2r.conf
		Valid options: 
			CRITICAL|HIGH|MEDIUM|LOW|TEST

Recovery:
	In case of loss of connectivity to the Resilient ticketing system, if configured to do so, will store events as queue items.
	When the system becomes available, and a new event triggers, the script will attempt to insert queued events.
	You can configure the behavior in the configuration options, under [recovery].

	You may also elect, in addition to the queue, sending emails of these events to a mailbox.
	You will only get notices of new failed events. Failed processing of queued events does not occur.

	You can check the queue by executing  /<splunk installation>/bin/scripts/s2r.py --check-queue
	Will return number of stored events.

	You can attempt to send stored events by excuting /<splunk installation>/bin/scripts/s2r.py --process-queue

Other:
	Modules tabulate.zip and requests.zip are loaded with the script during execution.
	They are provided with the script as python2.7 may not have these modules installed.
	This is to help resolve dependancies.