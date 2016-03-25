#!/usr/bin/python
#Splunk alert script to generate Resilient events
__maintainer__  = '{Ministry of Promise}'
__version__     = 'Beta 0.7.0'

try:
    import sys, os
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.poolmanager import PoolManager
    import traceback, errno
    import logging, logging.handlers
    import argparse
    import ConfigParser
    import glob, platform
    import re
    import datetime, time
    from calendar import timegm
    import gzip
    import csv
    import hashlib, uuid
    import copy
    import ssl
    import json
    import collections
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    import pprint
except ImportError as err:
    print "Unable to import essential modules: {}".format(err)
    sys.exit(-1)

class EventLogger:
    """
        Setup the logger to be used by the EventProcessor / EventParser / EventPush classes
        Creates root log instance, each module can append via .
        Example:

              Root              -> s2rLogger-localhost
              EventProcessor    -> s2rLogger-localhost.EventProcessor
              EventParser       -> s2rLogger-localhost.EventParser

            *Root name is set in config by the Logger handle
    """

    def __init__(self):
        try:
            # Read in Configuration
            execLocation    = os.path.dirname(os.path.abspath(__file__))
            configFile      = execLocation + '/s2r.conf'
            self.config     = ConfigParser.RawConfigParser()
            self.config.read(configFile)
            # Init Logger vars
            format          = self.config.get('logger', 'format')
            path            = self.config.get('logger', 'path')
            logname         = self.config.get('logger', 'logname')
            fullpath        = path+logname
            maxfilesize     = self.config.get('logger', 'maxfilesize')
            maxcopys        = self.config.get('logger', 'maxcopys')
            handle          = self.config.get('logger', 'handle')
            hostname        = self.config.getboolean('logger', 'hostname')
            level           = self.config.getint('logger', 'level')
            # Set Logger w/ vars
            handle          = handle+'-'+platform.node() if hostname else handle
            self.eLogger    = logging.getLogger(handle)
            self.eLogger.setLevel(level)
            # - FileHandler
            filehandler     = logging.handlers.RotatingFileHandler(fullpath, 
                                                                     mode='a',
                                                                     maxBytes=maxfilesize,
                                                                     backupCount=maxcopys)
            # - Formatter
            logformat       = logging.Formatter(format)
            filehandler.setFormatter(logformat)
            # - Debug Level
            filehandler.setLevel(level)
            # - Add handlers to logger
            self.eLogger.addHandler(filehandler)
            self.eLogger.info("Splunk2Resilient logger initialized via EventLogger - {}".format(handle))
        except Exception:
            traceback.print_exc()

class EventParser:
    """
        EventParser class extracts alert data from Splunk and transforms the data into digestible events.
        These event items can then be accessed in a standard way by other processes.

    """
    def __init__(self):
        #Get Configuration options
        execLocation    = os.path.dirname(os.path.abspath(__file__))
        configFile      = execLocation + '/s2r.conf'
        self.config     = ConfigParser.RawConfigParser()
        self.config.read(configFile)
        #Get existing logger root, create logger for EventParser Class
        hostname    = self.config.getboolean('logger', 'hostname')
        handle      = self.config.get('logger', 'handle')
        handle      = handle+'-'+platform.node() if hostname else handle
        loggerName  = handle+'.EventParser'
        self.log    = logging.getLogger(loggerName)
        self.log.debug('EventParser class initialized')

    def unpackEvents(self, event):
        """
            Take a given alert and unpack the results.csv.gz data file.
            Also removes system fields, those fields which start with 2 underscores '__'
            Returns list of dicts, these are events which triggered the alert
        """
        try:
            #Get file path of results.csv.gz
            csvFilePath     = event["file"]
            # - Validate file exist, otherwise complain
            if not os.path.isfile(csvFilePath):
                raise IOError("Unable to access file {}".format(csvFilePath))
            #Uncompress the file
            expandedFile    = gzip.open(csvFilePath, 'rb')
            #Read in CSV data => Key Value pairs
            rawCsvData      = csv.DictReader(expandedFile)
            #Iterate over each event, look at the Keys, remove any system Key Value pairs
            cleanCsvData    = map(lambda evnt: dict([(k,v) for k,v in evnt.items() if not k.startswith('__')]), rawCsvData)
            return cleanCsvData
        except Exception as err:
            self.log.warn("unpackEvents: {}".format(err))

    def processEvents(self, eventlist, event):
        """
            Take a list of events, [{keys,values}, {keys,values}]
            Processes list of events:
                1. Look for any fields w/ focus - Keys with a o_|oa_ prefix indicating focus or focus + artifact
                2. Transform event data into items for the eventsContainer
                    a.  Derive artifacts from events
                    b.  Derive priority from events (if present, otherwise default low)
                    c.  Create unique hash for each event, assign has to __ehash value
                3. Returns the eventsContainer, a list of events in a standard format
        """
        try:
            #Init Variables
            eventsContainer = []  #All events will be stored in a list
            alertName       = event['name']
            alertUrl        = event['url']
            alertQuery      = event['query']
            alertCount      = event['count']
            alertTerms      = event['terms']

            #Make record of this alert being processed
            self.log.debug("Processing alert: {}, see more at {}".format(alertName, alertUrl))

            #Update alert priority based on tile
            # - Set Priority, if indicated in Alert Title ex: [ALERT-NAME-HERE HIGH], Defaults to LOW
            if re.match('^\[[\w\s-]*(CRITICAL|HIGH|MEDIUM|LOW|TEST)\]', alertName):
                priority = re.match('^\[[\w\s-]*(CRITICAL|HIGH|MEDIUM|LOW|TEST)\]', alertName).group(1)
            else:
                priority = self.config.get('system', 'dplevel')

            #All events in the eventContainer will have the following additional fields
            privateKeyFields = {
                                '__artifacts':  {}, 
                                '__ehash':      None, 
                                '__alert':      alertName,
                                '__url':        alertUrl,
                                '__query':      alertQuery,
                                '__count':      alertCount,
                                '__priority':   priority,
                                '__focus':      None,
                                '__events':     [],
                                '__timeutc':    timegm(datetime.datetime.utcnow().utctimetuple())*1000
                                } 

            #Get all the fields for this alert
            eventFields = [ef for ef in eventlist[0].keys()]
            #Are any of these fields a focus field?
            focusFields  = [ff for ff in eventFields if re.match("^o_|oa_", ff)]
            #Are any of these fields an artifact field?
            artFields   = [af for af in eventFields if re.match("^oa_|a_", af)]
            self.log.debug("Focus fields: {}, Artifact fields: {}, Event count: {}".format(focusFields, artFields, len(eventlist)))  

            #Create Containers based on unique __focus fields / events
            if focusFields:
                # - Create place to hold focus events untill processing is completed
                tempcontainer = {}
                uniquefocusfields =  []

                #- Iterate over events looking for unique focus fields
                for xevent in eventlist:
                    #Take event and look for unique focus field-attribute, add not exists, create it.
                    for xkey, xvalue in xevent.items():
                        # - If key (kvf) is a focus field, but not in uniquefocusfields array, add it, 
                        # - also create container for focus event, add event to container
                        kvfkey = str(xkey)+': '+str(xvalue)
                        if (xkey in focusFields) and (kvfkey not in uniquefocusfields):
                            uniquefocusfields.append(kvfkey)
                            newcontainer = copy.deepcopy(privateKeyFields)
                            newcontainer['__focus'] = kvfkey
                            newcontainer['__events'].append(copy.deepcopy(xevent))
                            tempcontainer[kvfkey] = newcontainer
                        # - Is focus, and we have a unique focus key, add event to existig container
                        elif (xkey in focusFields) and (kvfkey in uniquefocusfields):
                            tempcontainer[kvfkey]['__events'].append(xevent)

                #Finnish processing events w/ focused fields       
                # - Strip unique focus field key from tempcontainer events
                # - Process artifacts for events in tempcontainer
                # - Create ehash values for events
                # - Add records to eventsContainer
                for ekey, evalue in tempcontainer.items():
                    
                    #Process Artifacts
                    artifacts = {}
                    # - Iterate over events in container and derive artifacts
                    for xitems in evalue['__events']:
                        for k,v in xitems.items():
                            if k in artFields:
                                artitems = self.deriveArtifacts(v)
                                artifacts.update(artitems)
                    # - Add found artifacts to container
                    evalue['__artifacts'].update(artifacts)

                    #Calculate and add eHash value to event
                    # - Take sorted(ekey+query+alertname) -> hash
                    prehash = ''.join(sorted([ekey, alertQuery, alertName]))
                    ehash = hashlib.md5(prehash).hexdigest()
                    evalue['__ehash'] = ehash

                    #Add event container to the main eventsContainer
                    eventsContainer.append(evalue)

            #Process events which have no focus field
            else:

                # - Wrap event in a new container -> privateKeyFields
                # - Process artifacts for event, if exists
                # - Add ehash value
                # - Add record to eventsContainer

                #Iterate over events
                for xevent in eventlist:
                    #Take event and wrap it
                    newcontainer = copy.deepcopy(privateKeyFields)
                    newcontainer['__events'].append(xevent)
                    
                    #Process Artifacts
                    artifacts = {}
                    # - Iterate over events in container and derive artifacts
                    for k,v in xevent.items():
                        if k in artFields:
                            artitems = self.deriveArtifacts(v)
                            artifacts.update(artitems)
                    # - Add found artifacts to container
                    newcontainer['__artifacts'].update(artifacts)

                    #Calculate and add eHash value to event
                    # - See if event has atrtifacts, if so do -> sorted(artifacts, query, alertname)
                    # - Else use results, query, alertname
                    if artifacts:
                        artjoin =  ''.join([str(x)+str(y) for x,y in sorted(artifacts.items())])
                        prehash =  ''.join(sorted([artjoin, alertQuery, alertName]))
                    else:
                        resultsjoin = ''.join([str(x)+str(y) for x,y in sorted(xevent.items())])
                        prehash     = ''.join(sorted([resultsjoin, alertQuery, alertName]))
                    #Add computed ehash to event container
                    ehash = hashlib.md5(prehash).hexdigest()
                    newcontainer['__ehash'] = ehash

                    #Add event container to the main eventContainer
                    eventsContainer.append(newcontainer)

            #Return eventsContainer
            self.log.info("{} Created {} incident events for processing".format(alertName, len(eventsContainer)))
            return eventsContainer
        except Exception as err:
            self.log.warn("processEvents: {}".format(err))
            traceback.print_exc()

    def deriveArtifacts(self, item):
        """
            Take input item and find its corrisponding artifact match
            If none are found, we default to a string type of 29
            returns {fieldvalue : type}
        """
        #Artifact Regular Expressions
        ip          = re.compile('^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(:([\d]{1,5})(/|$)|/|$)')
        dns         = re.compile('^(?:[-A-Z0-9]+\.)+[A-Z]+$', re.IGNORECASE)
        url         = re.compile('[A-Z]+:\/\/(?:[-A-Z0-9]+\.)+[A-Z]+(?:\:\d{2,5}\/|\/)+.*', re.IGNORECASE)
        email       = re.compile('.*@.*')
        malwaremd5  = re.compile('^[A-F0-9]{32}$', re.IGNORECASE)
        malwaresha1 = re.compile('[A-F0-9]{40}', re.IGNORECASE)
        useraccnts  = re.compile('^[A-Z]{2,8}\d?$', re.IGNORECASE) #This regex needs work, might as well be string 29

        #Artifact types, where the key represents the type id used in Resilient
        artifactRegs = {
                        1: ip,
                        2: dns,
                        3: url,
                        4: email,
                        13: malwaremd5,
                        14: malwaresha1,
                        }
        #Extract Artifact from item, defaults to string
        for regTestKey in artifactRegs.keys():
            regTestValue = artifactRegs[regTestKey]
            if regTestValue.match(item):
                #Return matching value key type
                return {item: regTestKey}
        else:
            #If all else fails, return string type
            return {item: '29'}

class EventPusher:
    """
        EventPuser class takes prcessed events and attempts to send them to Resilient.
    """
    def __init__(self):
        try:
            #Get Configuration options
            execLocation    = os.path.dirname(os.path.abspath(__file__))
            configFile      = execLocation + '/s2r.conf'
            self.config     = ConfigParser.RawConfigParser()
            self.config.read(configFile)
            #Get existing logger root, create logger for EventParser Class
            hostname    = self.config.getboolean('logger', 'hostname')
            handle      = self.config.get('logger', 'handle')
            handle      = handle+'-'+platform.node() if hostname else handle
            loggerName  = handle+'.EventPusher'
            self.log    = logging.getLogger(loggerName)
            self.log.debug('EventPusher class initialized')
            #Connection Specific Variables
            self.verifyssl   = self.config.getboolean('resilient', 'verifyssl')
            self.proxy       = {"https" : self.config.get('resilient', 'proxy')}
            self.timeout     = self.config.getint('resilient', 'timeout')
            #Style and Layout Variables
            self.splunktablelayout  = self.config.getboolean('system', 'splunktablelayout')
            self.splunkquerybreak   = self.config.getboolean('system', 'splunkquerybreak')
            #Other variables
            self.session  = requests.Session()
            self.session.mount('https://', TLSHttpAdapter())
            self.headers  = {'content-type': 'application/json'}
            self.cookies  = None
            self.userid   = None
            self.orgid    = None
            self.hostPath = None
            #Recovery Options
            self.sendEmails     = self.config.getboolean('recovery', 'sendemail')
            self.queueEvents    = self.config.getboolean('recovery', 'queuemsgs')
            self.sendOnUp       = self.config.getboolean('recovery', 'sendonup')
            self.xprint         = pprint.PrettyPrinter(depth=4)
        except Exception as err:
            self.log.warn("Unable to init EventPusher: {}".format(err))
            traceback.print_exc()

    def connect(self, hostname=None, port=None, username=None, password=None, verifyssl=False, orgname=None, proxy=None, timeout=None, test=False):
        """
            Make connection to Resilient ticketing system
        """
        try:
            #Set Connection Variables
            hostname     = hostname if hostname else self.config.get('resilient', 'host')
            port         = port if port else self.config.get('resilient', 'port')
            username     = username if username else self.config.get('resilient', 'user')
            password     = password if password else self.config.get('resilient', 'pass')
            orgname      = orgname if orgname else self.config.get('resilient', 'orgname')
            verifyssl    = verifyssl if verifyssl else self.verifyssl
            proxy        = proxy if proxy else self.proxy
            timeout      = timeout if timeout else self.timeout
            credentials  = {'email': username, 'password': password}

            #Make Connection
            self.hostURI = 'https://'+hostname+':'+port
            response = self.session.post("{0}/rest/session".format(self.hostURI), 
                                        data=json.dumps(credentials),
                                        proxies=proxy,
                                        headers=self.headers,
                                        verify=verifyssl,
                                        timeout=timeout)
            #Make sure connection returns status 200, otherwise complain
            if response.status_code != 200: 
                raise Exception("{}:  {}".format(response.reason, response.text))

            #Turn returned JSON data to a python dict() for easy access
            jsonData = json.loads(response.text)
            #Ensure our users org is available per this session, otherwise complain, also get orgid from jsondata
            if not orgname in [org['name'] for org in jsonData['orgs']]:
                raise Exception("Unable to access org group '{}'' for username '{}', check user configuration".format(orgname, username))
            else:
                self.orgid = [x['id'] for x in jsonData['orgs'] if x['name'] == orgname][0]

            #Set Headers and Cookies
            self.headers['X-sess-id'] = jsonData['csrf_token']
            self.cookies = {'JSESSIONID': response.cookies['JSESSIONID']}
            #Prints json response for testing, if set True
            if test:
                self.xprint.pprint(jsonData)
            return jsonData
        except Exception as err:
            self.log.warn("{}".format(err))
            if test:
                print "Failure: Unable to connect check logs:\n{}".format(err)
        
    def executeRequest(self, method, url, **kwargs):
        """
            Craft https call to Resilent ticketing system via the current session.
            Used by other calls doing GET/POST/PUT/DEL
        """
        try:
            #Ensure we have established connection params, aka we've connected
            if not self.hostURI:
                self.connect()
            #Options we can choose when constructing call
            options = {
                       'POST' : self.session.post,
                       'GET'  : self.session.get,
                       'PUT'  : self.session.put,
                       'DEL'  : self.session.delete
                       }       
            results = options[method](url, 
                                    proxies=self.proxy,
                                    cookies=self.cookies,
                                    headers=self.headers,
                                    verify=self.verifyssl,
                                    timeout=self.timeout,
                                    **kwargs)
            #Ensure request is Authorized, otherwise retry w/ reconnection
            if results.status_code == 401:
                self.log.debug('Attempting to reauthorizing session for request: {}'.format(url))
                self.connect()
                results = options[method](url, 
                                        proxies=self.proxy,
                                        cookies=self.cookies,
                                        headers=self.headers,
                                        verify=self.verifyssl,
                                        timeout=self.timeout,
                                        **kwargs)
            #Make sure connection returns status 200, otherwise complain
            if results.status_code != 200:  
                    raise Exception("{}: {}".format(results.reason, results.text))
            return results
        except Exception as err:
            self.log.warn(err)

    def searchForEventHash(self, ehash):
        """
            Searches Resilent ticketing system for the existance of ehash.
            Returns list with ids (ints) of open tickets, else False
            [id, id, id,...] 
            Should only be one entry in matches section if any are active
            if empty, no open tickets with matching event hash
        """
        try:
            #Search Query for Event Hash in Incidents, that are closed
            query = {
                    "filters": [{
                        "conditions": [{
                            "field_name": "properties.event_hash",
                            "method": "in",
                            "value": ehash
                        },{
                            "field_name": "plan_status",
                            "method": "equals",
                            "value": "A"
                        }]
                    }]
                }
            #URI to perform the search
            url     = "{0}/rest/orgs/{1}/incidents/query".format(self.hostURI, self.orgid)
            payload = json.dumps(query)
            results = self.executeRequest('POST', url, data=payload)

            #Process results, see if the hash exists in system
            rvalues  = []
            jsonData = json.loads(results.text)
            for xitem in jsonData:
                xid = xitem['id']
                rvalues.append(xid)
            #Warn that we've seen something odd here
            if len(rvalues) > 1:
                self.log.warn("Multiple incidents open with matching event hashes")
            return rvalues
        except Exception as err:
            self.log.warn(err)
            return False

    def sendEvents(self, events, recovery=False):
        """
            Inserts Events as tickets into Resilent.
            Takes list of events, and processes them to tickets w/ logic to handle failures
            If event is already in system, and active, becomes milestone event
            *If recovery is true, on the event of failure we dont process emails or re-dump the events
        """
        try:
            #Turn event list into a deque object, we do this for a dynamic list, allows allows threading later
            dque = collections.deque(events)
            self.log.info("Attemping to send {} incident events to Resilent".format(len(dque)))
            #Linear processing, one event at a time
            while True:
                try:
                    #Get next event from queue
                    event   = dque.pop()
                    #Check to see if event already exists, if not insert it
                    exists  = self.searchForEventHash(event['__ehash'])
                    if exists:
                        eid    = exists[0]
                        result = self.insertMileStone(event, eid)
                        if not result:
                            #Add event back to queue, as it failed to be processed
                            dque.append(event)
                            if self.sendEmails  and not recovery: self.failureSendEmail(events)
                            if self.queueEvents and not recovery: self.failureDumpEvents(events)
                            raise Exception("Unable to create milestone event, see logs")
                    else:
                        #Insert new Incident record
                        result = self.insertIncident(event)
                        if not result:
                            #Add event back to queue, as it failed to be processed
                            dque.append(event)
                            if self.sendEmails  and not recovery: self.failureSendEmail(events)
                            if self.queueEvents and not recovery: self.failureDumpEvents(events)
                            raise Exception("Unable to create incident for event, see logs")
                except IndexError as ierr:
                    #This is here by design, if there are no more items in queue, we end our loop
                    break
            return True
        except Exception as err:
            self.log.critical("Unable to send events to Resilent: {}".format(err))
            return False

    def insertMileStone(self, incident, incId):
        """
            If Incident is already open, add a milestone event to existing ticket
            Returns id of created milestone
            Returns False if error occured, see log for details
            Take incident record, and id of existing incident record which it will append against.
            ***You cannot add ANY formatting to Milestone entires, so its vanilla as possible!
        """
        try:
            #URI to perform the creation of the incident milestone. 
            url     = "{0}/rest/orgs/{1}/incidents/{2}/milestones/".format(self.hostURI, self.orgid, incId)
            #Generate string to append to milestone
            details = "Event recieved by splunk matching this open event: {}".format(incident['__url'])
            #Milestone json template
            milestoneTemplate = {
                        "title": incident['__alert'],
                        "description": {
                            "format" : "text",
                            "content": details
                        },
                        "date": int(incident['__timeutc'])
                    }   
            #Insert into ticket
            payload   = json.dumps(milestoneTemplate) 
            results   = self.executeRequest('POST', url, data=payload)
            jsonData  = json.loads(results.text)
            self.log.info("Added Milestone event for ticket {}".format(incId))
            return jsonData['id']

        except Exception as err:
            self.log.warn("Unable to add milestone to ticket: {}, see error: {}".format(incId, err))

    def insertIncident(self, incident):
        """
            Process incident into a json statement, then insert incident into system
            Returns False if error occured, see log for details
            Returns id of created incident
            *This function makes 2 calls.  1st call creates incident ticket, second adds addition details
        """
        try:
            #Init variable
            incidentNumber = False

            try:
                #Step One - Create Incident ticket
                #URI to perform the initial creation of the incident ticket. 
                url     = "{0}/rest/orgs/{1}/incidents/".format(self.hostURI, self.orgid)
                #SeverityCodes - 56(High), 55(Medium), 54(Low)
                severityMap      = { "HIGH" : 56, "MEDIUM" : 55, "LOW" : 54}
                incidentTemplate = {
                                    "name": incident['__alert'],
                                    "discovered_date": int(incident['__timeutc']),
                                    "description" : self.processDescription(incident),
                                    "artifacts" : self.processArtifacts(incident, out='json'),
                                    "properties" : { 
                                        "event_hash": incident['__ehash']
                                    },
                                    "severity_code": severityMap[incident['__priority']]
                                }
                payload = json.dumps(incidentTemplate) 
                results = self.executeRequest('POST', url, data=payload)
                jsonData = json.loads(results.text)
                incidentNumber = jsonData["id"]
                self.log.info("Added Incident ticket {}".format(incidentNumber))

            except Exception as err:
                self.log.warn("Unable to create initial incident ticket: {}".format(err))
                raise Exception("Ticket creation encountered issues when creating incident: {}".format(err))

            try:
                #Step Two, Create a note w/ more details
                #Concat all the outputs to a note
                details = self.processDescription(incident)+self.processArtifacts(incident, out='html')+self.processQuery(incident)+self.processSpunkTable(incident)
                url     = "{}/rest/orgs/{}/incidents/{}/comments".format(self.hostURI, self.orgid, incidentNumber)
                payload = json.dumps({"text" : { "format" : "html", "content" : details}})
                results = self.executeRequest('POST', url, data=payload)
                self.log.info("Added additional details to Incident ticket {} succesfully".format(incidentNumber))
                
            except Exception as err:
                self.log.warn("Unable to add detials to ticket: {}".format(err))
                raise Exception("Ticket creation encountered issues when adding notes: {}".format(err))

            return incidentNumber   
        except Exception as err:
            self.log.warn("Unable to complete ticket creation: {}".format(err))
            return False

    def failureDumpEvents(self, events):
        """
            Incase we are unable to communicate with the Resilent ticketing system, we need to store these events.
            Each set of events will get dumped to a unique file s2r_queued_<uniqueuuid>.json
            Takes eventsContainer object and parses event data to json for storage.
            Returns filename of dumped events.
        """
        try:
            #Create unique file name for dump
            filename    = 's2r_queued_'+str(uuid.uuid4())+'.json'
            qdir        = self.config.get('recovery', 'queuedir')
            filename    = qdir + filename
            #Write Events from Alert out to file
            json.dump(events, open(filename, 'wb+'), sort_keys=True, indent=2, separators=(',', ': '))
            self.log.debug('Dumped events to file: {}'.format(filename))
            return filename
        except Exception as err:
            self.log.war(err)

    def failureLoadEvents(self, count=None, override=False):
        """
            If we where unable to communicate with the Resilent ticketing system, we likely dumped alert events to a file.
            Look to see if any s2r_queued_<uuid>.json files exists in current directory, if so load them into a event Container.
            After succesful tranmition of events, remove the s2r_queued_ files from system
            If unsuccesful, leave files

            If count is True, returns count of queued events in queue files, then exits
        """
        lockaquired = False
        #Exit if we dont want to attempt recovery - sendonup == True in config file
        # - If override is set True, attempt to process queue events if they exists
        if not self.sendOnUp and not count:
            if not override:
                self.log.info("Not sending queued events, option disabled in config") 
                sys.exit(0)
        try:
            #Get directory where alert events are being written.
            qdir = self.config.get('recovery', 'queuedir')
            #Lock & prevent any other failureLoadEvents from performing this task
            eventList = []
            if self.getLock():
                #Let the "finally" block know we got the lock, remove it no matter what happens!
                lockaquired = True
                #Create list of files to read in then delete if successful
                fileList = glob.glob(qdir+"s2r_queued_*.json")
                #Search for files matching s2r queue
                for xfile in fileList:
                    out = json.load(open(xfile, 'r'))
                    for xevent in out:
                        eventList.append(xevent)
                #If count is true, return count of queued events
                if count:
                    print len(eventList)
                    sys.exit(0)
                self.log.info("Loaded {} events from queued objects.".format(len(eventList)))
                if eventList:
                    #Attempt to re-send events via sendEvents(eventList, recovery=True)
                    validate = self.sendEvents(eventList, recovery=True)
                    if not validate:
                        self.log.warn("Unable to processed recovery queue, system may still be unavailable")
                    else:
                        self.log.info("Processed recovery queue, removing queue files")
                        try:
                            #Remove processed queue files
                            for rmfile in fileList:
                                os.remove(rmfile)
                        except Exception as err:
                            self.log.critical("Unable to remove queue files! See error: {}".format(err))
                else:
                    #Log there were no queue items to process
                    self.log.info("Recovery queue contained no events to process.")
        except Exception as err:
            self.log.warn(err)
        finally:
            #Ensure we remove the lock, incase there was an error
            if lockaquired: self.delLock()

    def failureSendEmail(self, events):
        """
            Process events into messages which can be sent to an email address.
            Sends html based messages
        """
        #Variables
        sender      = self.config.get('recovery', 'sender')
        recipient   = self.config.get('recovery', 'recipient')
        self.log.info("Sending events via Email")
        try:        
            #If we have a large number of events > 10, add delay.
            isBulk = True if len(events) >= 10 else False
            if isBulk: self.log.info("Bulk number of events detected, adding delay per email")
            #Process events, then mail them out
            for xvnt in events:
                #Process HTML for this event
                htmlmsg =  "<html>"
                htmlmsg += self.processDescription(xvnt)
                htmlmsg += self.processArtifacts(xvnt, out='html')
                htmlmsg += self.processQuery(xvnt)
                htmlmsg += self.emailSpunkTable(xvnt)
                htmlmsg += "</html>"

                subject = "Splunk2Resilient: {}, failed to send to Resilent".format(xvnt['__alert'])
                #We send HTML formatted emails
                self.mailer(recipient, sender, subject, htmlmsg=htmlmsg)
                #Insert artificial delay of 0.5sec/email, if a LARGE number of emails are generated, we dont want to get locked out.
                if isBulk:
                    time.sleep(0.5)
        except Exception as err:
            self.log.critical(err)

    def getLock(self):
        """
            Attempts to create file s2r.lck if it doesnt already exists.
            If it does exists, failed to get lock (likley already exists), returns False
                If lock exists, validate timestamp of lockfile is NOT OVER 90 seconds. If so, delete!
            If it doesnt exists, will create the file and return True
            Note this is done in one step via os.open to ensure we dont encounter a race condition

            Return True; lock aquired
            Return False; not aquired
        """
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            flock = os.open('s2r.lck', flags)
            self.log.debug('Aquired lock - s2r.lck')
        except OSError as err:
            #Does the file already exists?
            if err.errno == errno.EEXIST:
                self.log.info('Unable to aquire lock, existing lock in place')
                #We are going to double check the locks timestamp is not over 90 seconds from current epoch
                #If so, we are going to blow it away, as its BAD (no lock should exist over 120 seconds)
                #If we cannot read the timestamp, we are going to blow it away.
                try:
                    with open('s2r.lck', 'r') as lckfile:
                        oldEpoch = int(lckfile.read())
                        if int(time.time()) - oldEpoch >= 90:
                            self.log.warn('Attempting to remov old lock file, is over 90 seconds old')
                            self.delLock()
                except:
                    self.log.warn('Unable to read timestamp on lock file, deleting lock')
                    self.delLock()

                return False
            else:
                self.log.info('Unable to set lock, see error: {}'.format(err))
                return False
        #We created the lockfile, make epoch note, close file, return True
        else:
            with os.fdopen(flock, 'w') as lck:
                lck.write(str(int(time.time()))) #write epoch to file
                self.log.debug('Lock aquired')
            return True

    def delLock(self):
        """
            Attempts to delete lock file
            Return True; File was deleted
            Return False; File was unable to be deleted
        """
        try:
            os.remove('s2r.lck')
            self.log.debug('Deleted aquired lock - s2r.lck')
            return True
        except Exception as err:
            self.log.warn("Unable to remove lock file: {}".format(err))
            return False

    def mailer(self, recipient, sender, subject, txtmsg=None, htmlmsg=None):
        """
            Generic smtp email client
            Requires recipient / sender / subject
            Can send text or html messages (or both) via txtmsg and htmlmsg
            Returns True on send, otherwise raises Exception
        """
        try:
            # Create message container
            msg             = MIMEMultipart('alternative')
            msg['Subject']  = subject
            msg['From']     = sender
            msg['To']       = recipient
            if txtmsg:
                msg.attach(MIMEText(txtmsg, 'plain'))
            if htmlmsg:
                msg.attach(MIMEText(htmlmsg, 'html'))
            #Send Message
            mailrelay = self.config.get('recovery', 'mailrelay')
            snd       = smtplib.SMTP(mailrelay)
            snd.sendmail(sender, recipient, msg.as_string())
            snd.quit()
            self.log.info("Email sent to {} w/ subject of: '{}'".format(recipient, subject))
            return True
        except Exception as err:
            self.log.warn("Unable to send email: {}".format(err))
            raise Exception(err)

    def emailSpunkTable(self, incident):
        '''
            Incident splunk table process
            Takes incident, returns HTML formatted table of Splunk output for email, otherwise raises exception
        '''
        try:
            #Create HTML based table w/o table elements compatible with Resilient
            # - A bit hackish, but it works
            tabledata  = incident['__events']
            headers    = tabledata[0].keys()

            #Determing output by output option set in config file True-> Horizontal / False-> Vertical
            if self.splunktablelayout:
                #Construct Horizontal Table
                # - Table Variables
                output = "<br/><b>Splunk Results Table</b><br/><table cellpadding='1' cellspacing='2' style='border: 1px solid black;'>"
                tblrow = "<tr>{}</tr>"
                #Cell Style
                # Args for Template, additional sytle details, cell contents
                tblcll = "<td style='{}'>{}</td>"

                # - Construct the Table header
                tmpout = ""
                # - Set cell style
                style  = "border: 1px solid black;font-weight:bold;color: black;background-color: #6ca146;padding: 8px;"
                for xheadr in headers:
                    tcell  = tblcll.format(style, '{}')
                    tmpout += tcell.format(xheadr)
                output += tblrow.format(tmpout)

                # - Construct the Table rows
                cntr = 2
                for event in tabledata:
                    tmpout = ""
                    # - Set cell style
                    if cntr % 2 == 0:
                        style = "border: 1px solid black;color: black;background-color: #ffffff;"
                        tcell = tblcll.format(style, '{}')
                    else:
                        style = "border: 1px solid black;color: black;background-color: #d9d9d9;"
                        tcell = tblcll.format(style, '{}')

                    for cell in event.values():
                        tmpout += tcell.format(cell)
                    output += tblrow.format(tmpout)
                    cntr += 1

                # - End of Table
                output += "</table>"
            else:
                #Construct Vertical Table
                # - Table Variables
                output = "<br/><b>Splunk Results Table</b><br/><table width='350' border='1' cellpadding='1' cellspacing='2'>"
                tblrow = "<tr>{}</tr>"
                #Cell Style
                # Args for Template, additional sytle details, cell contents
                tblcll  = "<td style='{}'>{}</td>"

                cntr = 2
                for event in tabledata:
                    
                    # - Color code groups for easier reading
                    if cntr % 2 == 0:
                        vstyle  = "border: 1px solid black;background-color: #d9d9d9;"
                        vcell   = tblcll.format(vstyle, '{}')
                        kstyle  = "border: 1px solid black;color: black;background-color: #6ca146;"
                        kcell   = tblcll.format(kstyle, '{}')
                    else:
                        vstyle  = "border: 1px solid black;background-color: #ffffff;"
                        vcell   = tblcll.format(vstyle, '{}')
                        kstyle  = "border: 1px solid black;color: black;background-color: #86b960;"
                        kcell   = tblcll.format(kstyle, '{}')
                    # 
                    # - Build out vertical table
                    for k, v in event.items():
                        tmpout = ""
                        # - Write the Kvalue
                        tmpout += kcell.format(k)
                        # - Write the Vvalue
                        tmpout += vcell.format(v)
                        # - Add it to a row group, then to output, cont
                        output += tblrow.format(tmpout)

                    cntr += 1

                else:
                    # - End of Table
                    output += "</table>"

            return output
        except Exception as err:
            self.log.warn(err)
            raise Exception("Encountered issues when processing splunk table: {}".format(err))

    def processDescription(self, incident):
        '''
            Incident description process
            Takes incident, returns HTML formatted table of description output, otherwise raises exception
        '''
        try:
            #Get all header information, this will make up the details, -events - artifacts -query
            descString = "<b>Splunk Generated Event</b><br/><ol style='list-style-type:circle'>"
            for key, value in incident.items():
                if not key in ['__events','__query', '__artifacts']:
                    if key == "__url":
                        try:
                            idxHtml     =  str(value).index("__search__")+10
                            descString  += "<li><b>Splunk Link:</b>&nbsp;<a href='{}' target='_blank'>{}</a></li>".format(str(value), str(value)[idxHtml:])
                        except Exception as err:
                            self.log.warn("Unable to parse query url - [{}] error - {}, using unparsed value.".format(value, err))
                            descString += "<li><b>Splunk Link:</b>&nbsp;<a href='{0}' target='_blank'>{0}</a></li>".format(str(value))
                    elif key == "__timeutc":
                        utcTimeStamp  = int(int(value)/1000)
                        dt            = datetime.datetime.utcfromtimestamp(utcTimeStamp)
                        displayString = "{0:02d}:{1:02d}:{2:02d} {3:02d}/{4:02d}/{5}".format(dt.hour,dt.minute,dt.second,dt.month,dt.day,dt.year)
                        descString    += "<li><b>Time UTC:</b>&nbsp;{}</li>".format(displayString)
                    else:
                        descString    += "<li><b>{}:</b>&nbsp;{}</li>".format(key[2:].title(), str(value))
            else:
                descString += "</ol><br></div>"
            return descString
        except Exception as err:
            self.log.warn(err)
            raise Exception("Encountered issues when processing description: {}".format(err))

    def processArtifacts(self, incident, out=None):
        '''
            Incident artifact table process
            Takes incident, returns HTML or JSON formatted table of Artifact output, otherwise raises exception
        '''
        try:
            #Processes Artifact information as JSON or HTML
            #- Set out='json' or out='html' for return type.
            if not out:
                return None
            if out == 'json':
                #Get all header information, this will make up the details, -events - artifacts -query
                json = [{"type": int(aid), "value": avalue} for avalue, aid in incident['__artifacts'].items()]
                return json
            if out == 'html':
                artCodes = {
                        1: "IP Address",
                        2: "DNS",
                        3: "URL",
                        4: "eMail",
                        13: "Malware MD5",
                        14: "Malware SHA1",
                        29: "String"
                        }
                artString  = "<b>Artifacts</b><br/>"
                artString += "".join(["<b>{}:</b>&nbsp;&nbsp;{}<br/>".format(artCodes[int(aid)],avalue) for avalue, aid in incident['__artifacts'].items()])
                artString += "<br/>"
                return artString
        except Exception as err:
            self.log.warn(err)
            raise Exception("Encountered issues when processing artifacts: {}".format(err))

    def processSpunkTable(self, incident):
        '''
            Incident splunk table process
            Takes incident, returns HTML formatted table of Splunk output, otherwise raises exception
        '''
        try:
            #Create HTML based table w/o table elements compatible with Resilient
            # - A bit hackish, but it works
            tabledata  = incident['__events']
            headers    = tabledata[0].keys()

            #Determing output by output option set in config file True-> Horizontal / False-> Vertical
            if self.splunktablelayout:
                #Construct Horizontal Table
                # - Table Variables
                output = "<br/><b>Splunk Results Table</b><br/><div style='display: table;border-top: 1px solid black;border-left: 1px solid black;'>"
                tblrow = "<div style='display: table-row-group;'>{}</div>"
                #Cell Style
                # Args for Template, additional sytle details, cell contents
                tblcll = "<div style='display: table-cell;font-weight:light;text-align:center;color: black;border-right: 1px solid black;border-bottom: 1px solid black;{}'>{}</div>"

                # - Construct the Table header
                tmpout = ""
                # - Set cell style
                style  = "font-weight:bold;font-size:90%;color: black;background-color: #6ca146;padding: 8px;"
                for xheadr in headers:
                    tcell  = tblcll.format(style, '{}')
                    tmpout += tcell.format(xheadr)
                output += tblrow.format(tmpout)

                # - Construct the Table rows
                cntr = 2
                for event in tabledata:
                    tmpout = ""
                    # - Set cell style
                    if cntr % 2 == 0:
                        style = "font-size:85%;color: black;background-color: #f2f2f2;padding: 5px;"
                        tcell = tblcll.format(style, '{}')
                    else:
                        style = "font-size:85%;color: black;background-color: #d9d9d9;padding: 5px;"
                        tcell = tblcll.format(style, '{}')

                    for cell in event.values():
                        tmpout += tcell.format(cell)
                    output += tblrow.format(tmpout)
                    cntr += 1

                # - End of Table
                output += "</div>"

            else:
                #Construct Vertical Table
                # - Table Variables
                output = "<br/><b>Splunk Results Table</b><br/><div style='display: table;border-top: 1px solid black;border-left: 1px solid black;'>"
                tblrow = "<div style='display: table-row-group;'>{}</div>"
                #Cell Style
                # Args for Template, additional sytle details, cell contents
                tblcll  = "<div style='display: table-cell;border-right: 1px solid black;border-bottom: 1px solid black;{}'>{}</div>"

                cntr = 2
                for event in tabledata:
                    
                    # - Color code groups for easier reading
                    if cntr % 2 == 0:
                        vstyle  = "font-size:85%;background-color: #d9d9d9;text-align:center;font-weight:light;padding:2px;"
                        vcell   = tblcll.format(vstyle, '{}')
                        kstyle  = "font-size:90%;text-align:left;color: black;background-color: #6ca146;font-weight:bold;padding-left: 5px; padding-right: 10px;"
                        kcell   = tblcll.format(kstyle, '{}')
                    else:
                        vstyle  = "font-size:85%;background-color: #f2f2f2;text-align:center;font-weight:light;padding: 2px;"
                        vcell   = tblcll.format(vstyle, '{}')
                        kstyle  = "font-size:90%;text-align:left;color: black;background-color: #86b960;font-weight:bold;padding-left: 5px; padding-right: 10px;"
                        kcell   = tblcll.format(kstyle, '{}')
                    # 
                    # - Build out vertical table
                    for k, v in event.items():
                        tmpout = ""
                        # - Write the Kvalue
                        tmpout += kcell.format(k)
                        # - Write the Vvalue
                        tmpout += vcell.format(v)
                        # - Add it to a row group, then to output, cont
                        output += tblrow.format(tmpout)

                    cntr += 1

                else:
                    # - End of Table
                    output += "</div>"

            return output
        except Exception as err:
            self.log.warn(err)
            raise Exception("Encountered issues when processing splunk table: {}".format(err))

    def processQuery(self, incident):
        '''
            Incident splunk query process
            Takes incident, returns HTML formatted query otherwise raises exception
        '''
        try:
            #Some symbols will need to be replaced
            repsyms = {'<': '&lt;', '>':'&gt;'}
            query   = incident['__query']
            outText = "<b>Splunk Query</b><br/>"

            #Decide how we want to process the Splunk query
            # - True (Break on Newline chars) / False (Break on Pipe chars)
            if self.splunkquerybreak:
                #Clean up the Query Output, break on Newline Char
                cnt = len(query.split("\n"))
                for item in query.split("\n"):
                    #HTML escaping fix for symbols listed in repsym dict
                    for ritem in repsyms.items():
                        if ritem[0] in item:
                            item = item.replace(ritem[0], ritem[1])

                    cnt-=1
                    outText +=item+"<br/>" if cnt != 0 else item
                else:
                    outText +="<br/>"

            else:
                #Clean up the Query Output, break on the pipe |
                cnt = len(query.split("|"))
                for item in query.split("|"):
                    item = item.strip()
                    #HTML escaping fix for symbols listed in repsym dict
                    for ritem in repsyms.items():
                        if ritem[0] in item:
                            item = item.replace(ritem[0], ritem[1])
                    cnt-=1
                    outText +=item+"<br/>|" if cnt != 0 else item
                else:
                    outText +="<br/>"

            return outText
        except Exception as err:
            self.log.warn(err)
            raise Exception("Encountered issues when processing splunk query: {}".format(err))

class TLSHttpAdapter(HTTPAdapter):
    """
    Adapter that ensures that we use the best available SSL/TLS version.
    Some environments default to SSLv3, so we need to specifically ask for
    the highest protocol version that both the client and server support.
    Despite the name, SSLv23 can select "TLS" protocols as well as "SSL".
    """
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv23)

def checkQueue():
    '''
        Checks queue for items
        returns count
    '''
    queueCount = EventPusher().failureLoadEvents(count=True)
    print "Events in queue: {}".format(queueCount)
    sys.exit(0)

def processQueue():
    '''
        Checks queue for items and processes if possible
        returns None
    '''
    print "Attempting to process any queued events, see s2r log for details"
    eventpusher = EventPusher()
    eventpusher.connect()
    eventpusher.failureLoadEvents(override=True)
    sys.exit(0)

def testConnection():
    '''
        Checks connectivity to Resilient system from config file
        returns json of attempted connection
    '''
    EventPusher().connect(test=True)
    sys.exit(0)

def main(args):
    #If 9 args, Splunk event, begin processing
    if len(args) == 9:
        # - Gather Splunk event data as eventArgs
        eventArgs = {
                    "count"   : args[1],
                    "terms"   : args[2],
                    "query"   : args[3],
                    "name"    : args[4],
                    "trigger" : args[5],
                    "url"     : args[6],
                    "file"    : args[8]
                    }
        # - Start Event Parser
        eventparser     = EventParser()

        # - Unpack events
        unpackedEvents  = eventparser.unpackEvents(eventArgs)

        # - Process events into workable segments, packed in a container (list)
        eventContainer  = eventparser.processEvents(unpackedEvents, eventArgs)

        # - Start Event Pusher
        eventpusher     = EventPusher()

        # - Connect to Resilient
        eventpusher.connect()

        # - Attempt to send Event data to Resilient
        validate        = eventpusher.sendEvents(eventContainer)
        # Check for queued events, if validate == True, else pass on this step
        # Will not trigger if queuemsg is set to False in conf file.
        if validate:
            # Exit after attempt
            eventpusher.failureLoadEvents()

        # - End of Processing
        sys.exit(0)

    else:
        #Argument Parser
        parser = argparse.ArgumentParser(description='Splunk to Resilient - s2r.py', epilog="See README.txt for additional information.\n")
        parser.add_argument('-t', '--testconnection', action="store_true", help="Attempt to connect to Resilient, returns attempt information")
        parser.add_argument('-c', '--checkqueue', action="store_true", help='Check number of items in queue')
        parser.add_argument('-p', '--processqueue', action="store_true", help='Process items in queue')
        pargs = parser.parse_args()

        #Print Queue status
        if pargs.checkqueue: checkQueue()
        #Process Queue items
        if pargs.processqueue: processQueue()
        #Test connection to Resilient
        if pargs.testconnection: testConnection()

if __name__ == '__main__':
    # - Init/Start Logger
    EventLogger()
    # - Send event data to main
    main(sys.argv)