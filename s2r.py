#!/usr/bin/python
#Splunk alert script to generate Resilient events
__maintainer__  = '{Ministry of Promise}'
__version__     = 'Beta 0.5'
###################################
import sys, os
#Where does the splunk install live?
try:
    splunkHome = os.environ['HOME']
    scriptDirectory = splunkHome + '/bin/scripts'
    os.chdir(scriptDirectory)
    #Import requests module
    sys.path.insert(0, 'requests.zip')
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.poolmanager import PoolManager
    #Surpress warnings about SSL
    requests.packages.urllib3.disable_warnings()
    #Import tabulate module
    sys.path.insert(0, 'tabulate.zip')
    from tabulate import tabulate
except ImportError as err:
    print "Unable to import essential modules: {}".format(err)
    sys.exit(-1)
except OSError as err:
    print "Unable to access scripts directory for Splunk user: {}".format(err)
    print "Must be ran as Splunk user, with $HOME set to location of splunk intallation, typically located at /opt/splunk"
    sys.exit(-1)
###################################
import traceback, errno
import logging, logging.handlers
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

class EventLogger:
    """
        Setup the logger to be used by the EventProcessor / EventParser / EventPush classes
        Creates root log instance, each module can append via .
        Example:

              Root          -> s2rLogger-localhost
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
            self.eLogger.info("Splunk2Resilient logger initialized via EventLogger class")
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
            privateKeyFeilds = {
                                '__artifacts':  {}, 
                                '__ehash':      None, 
                                '__alert':      alertName,
                                '__url':        alertUrl,
                                '__query':      alertQuery,
                                '__count':      alertCount,
                                '__priority':   priority,
                                '__focus':  None,
                                '__events':     [],
                                '__timeutc':    timegm(datetime.datetime.utcnow().utctimetuple())*1000
                                } 

            #Get all the fields for this alert
            eventFields = [ef for ef in eventlist[0].keys()]
            #Are any of these fields a focus field?
            focusField  = [ff for ff in eventFields if re.match("^o_|oa_", ff)]
            #Are any of these fields an artifact field?
            artFields   = [af for af in eventFields if re.match("^oa_|a_", af)]

            # - Sanity check, ONLY 1 FOCUS, if more, spit warning and treat like un-focused events!
            if len(focusField) > 1:
                self.log.warn("Multiple focus fields used in alert query {}, switching to non-focused processing".format(alertName))
                focusField = []
            elif len(focusField) == 1:
                focusField = focusField[0]
                #Get all other event fields
                otherEventFields = [oef for oef in eventFields if not focusField in oef]

            #Processing events which have a focus field
            if focusField:
                #Process focused events into tmpContainer
                # - Temp var to hold events while being processed
                tempContainer   = {}
                for evntItem in eventlist:
                    #Create unique index field based off focus field name + field value
                    tmpKVpair = str(focusField) + str(evntItem[focusField])
                    uniqueKey = hashlib.md5(tmpKVpair).hexdigest()

                    #Check if focused item has already been added to the tempContainer
                    if tempContainer.has_key(uniqueKey):
                        #Append event entrie to existing alert key in the tempContainer
                        tempContainer[uniqueKey]['__events'].append(evntItem)
                        #Get artifacts from the event fields, if they have oa_ | a_ per artFields var
                        for art in artFields:
                            artifact = self.deriveArtifacts(evntItem[art])
                            tempContainer[uniqueKey]['__artifacts'].update(artifact)
                        #Insert eventItem values into __tmpehash bucket for ehash calculation, min pre processing w/ set & isNumber
                        tempContainer[uniqueKey]['__tmpehash'].update(set([ei for ei in evntItem.values() if not self.isNumber(ei)]))
                    else:
                        #Insert private key data structure into new alert entry in tempContainer
                        tempContainer[uniqueKey] = copy.deepcopy(privateKeyFeilds)
                        #Set __focus to focus Field
                        tempContainer[uniqueKey]['__focus'] = focusField
                        #Append event item to new alert entry in tmpContainer
                        tempContainer[uniqueKey]['__events'].append(evntItem)
                        #Get artifacts from the event fields, if they have oa_ | a_ per artFields var
                        for art in artFields:
                            artifact = self.deriveArtifacts(evntItem[art])
                            tempContainer[uniqueKey]['__artifacts'].update(artifact)
                        #Create temp field to store values for ehash calculation, min pre processing w/ set & isNumber
                        tempContainer[uniqueKey]['__tmpehash'] = set()
                        tempContainer[uniqueKey]['__tmpehash'].update(set([ei for ei in evntItem.values() if not self.isNumber(ei)]))
                
                #Need to iterate over all events in tempContainer to create ehashes, and remove __tmphash
                for tmpKey in tempContainer:
                    tmpElements = []
                    for item in tempContainer[tmpKey]['__tmpehash']:
                        tmpElements.append(item)
                    #Sort the tmpElements
                    tmpElements = sorted(tmpElements)
                    priHash = "".join(tmpElements)+alertQuery
                    ehash = hashlib.md5(priHash).hexdigest()
                    #Set ehash, remove tmphash
                    tempContainer[tmpKey]['__ehash'] = ehash
                    del(tempContainer[tmpKey]['__tmpehash'])

                #Strip off unique index from events, append to eventsContainer
                [eventsContainer.append(xe) for xe in tempContainer.values()]
            
            #Process events which have no focus field into the eventsContainer
            else:
                #temp eHash collection (experimental)
                ehashCollection = []
                ehashCollectionNotification = []
                for evntItem in eventlist:
                    #Copy private data structure into a container
                    container = copy.deepcopy(privateKeyFeilds)
                    #Append event entrie to the container
                    container['__events'].append(evntItem)
                    #Get artifacts from the event fields, if they have a_ per artFields var
                    for art in artFields:
                        artifact = self.deriveArtifacts(evntItem[art])
                        container['__artifacts'].update(artifact)
                    #Derive ehash value
                    # - Get unique elements from the event order(set(removes duplicates, and order them - int/floats)) + unique query string
                    # - Hash these values together.
                    # - If X query generates Y results, despite Yn..n, you can validate events are == via set(Y)s
                    # - Remove int/float values from eventItems, as Yn..n if Y = various n counts @ query time, this will skew dup detection
                    elements = sorted(set([ei for ei in evntItem.values() if not self.isNumber(ei)]))
                    priHash = "".join(elements)+alertQuery
                    ehash = hashlib.md5(priHash).hexdigest()
                    container['__ehash'] = ehash
                    # - Test to see if ehash exist already in ehashCollection, if so, recommend Query be updated w/ focal field or re-written
                    if not ehash in ehashCollection:
                        ehashCollection.append(ehash)
                    elif alertName not in ehashCollectionNotification:
                        self.log.info("Alert: {}, may need a focus field or re-tooling, generated duplicate ehash values!".format(alertName))
                        ehashCollectionNotification.append(alertName)
                    #Append event container to the eventsContainer
                    eventsContainer.append(container)

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

    def isNumber(self, item):
        """
            Test to see if item could be a int or float value
        """
        for xitem in range(1):
            try:
                if xitem == 0:
                    if int(item):
                        return True
                if xitem == 1:
                    if float(item):
                        return True
            except ValueError:
                continue
        else:
            return False

class EventPusher:

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
            self.proxy       = self.config.get('resilient', 'proxy')
            self.timeout     = self.config.getint('resilient', 'timeout')
            #Other variables
            self.session = requests.Session()
            self.session.mount('https://', TLSHttpAdapter())
            self.headers = {'content-type': 'application/json'}
            self.cookies = None
            self.userid  = None
            self.orgid  = None
            self.hostPath = None
            #Recovery Options
            self.sendEmails     = self.config.getboolean('recovery', 'sendemail')
            self.queueEvents    = self.config.getboolean('recovery', 'queuemsgs')
            self.sendOnUp       = self.config.getboolean('recovery', 'sendonup')
            self.xprint  = pprint.PrettyPrinter(depth=4)
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
            options = {'POST' : self.session.post,
                        'GET'  : self.session.get,
                        'PUT'  : self.session.put,
                        'DEL'  : self.session.delete}       
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
            rvalues = []
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
                    event = dque.pop()
                    #Check to see if event already exists, if not insert it
                    exists = self.searchForEventHash(event['__ehash'])
                    if exists:
                        eid = exists[0]
                        result = self.insertMileStone(event, eid)
                        if not result:
                            #Add event back to queue, as it failed to be processed
                            dque.append(event)
                            if self.sendEmails and not recovery: self.failureSendEmail(events)
                            if self.queueEvents and not recovery: self.failureDumpEvents(events)
                            raise Exception("Unable to create milestone event, see logs")
                    else:
                        #Insert new Incident record
                        result = self.insertIncident(event)
                        if not result:
                            #Add event back to queue, as it failed to be processed
                            dque.append(event)
                            if self.sendEmails and not recovery: self.failureSendEmail(events)
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
            payload = json.dumps(milestoneTemplate) 
            results = self.executeRequest('POST', url, data=payload)
            jsonData = json.loads(results.text)
            self.log.info("Added Milestone event for ticket {}".format(incId))
            return jsonData['id']

        except Exception as err:
            self.log.warn("Unable to add milestone to ticket: {}, see error: {}".format(incId, err))

    def insertIncident(self, incident):
        """
            Process incident into a json statement, then insert incident into system
            Returns False if error occured, see log for details
            Returns id of created incident
            *contains sub functions <process*> for pre-processing data
            *This function makes 2 calls.  1st call creates incident ticket, second adds addition details
        """
        def processDescription(incident):
            try:
                #Get all header information, this will make up the details, -events - artifacts -query
                descString = "<b>Splunk Generated Event</b><br/><olstyle='list-style-type:circle'>"
                for key, value in incident.items():
                    if not key in ['__events','__query', '__artifacts']:
                        if key == "__url":
                            idxHtml = str(value).index("__search__")+10
                            descString+="<li><b>Splunk Link:</b>&nbsp;<a href='{}' target='_blank'>{}</a></li>".format(str(value), str(value)[idxHtml:])
                        elif key == "__timeutc":
                            utcTimeStamp = int(int(value)/1000)
                            dt = datetime.datetime.utcfromtimestamp(utcTimeStamp)
                            displayString = "{}:{}:{} {}/{}/{}".format(dt.hour,dt.minute,dt.second,dt.month,dt.day,dt.year)
                            descString+="<li><b>Time UTC:</b>&nbsp;{}</li>".format(displayString)
                        else:
                            descString+="<li><b>{}:</b>&nbsp;{}</li>".format(key[2:].title(), str(value))
                else:
                    descString+="<br></div>"
                return descString
            except Exception as err:
                self.log.warn(err)

        def processArtifacts(incident, out=None):
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
                    artString += "<br>"
                    return artString
            except Exception as err:
                self.log.warn(err)

        def processSpunkTable(incident):
            try:
                #Create HTML based table w/o table elements compatible with Resilient
                # - A bit hackish, but it works
                tabledata   = incident['__events']
                headers     = tabledata[0].keys()

                #Construct Table
                # - Element vars
                startTable      = "<div style='display:table;'>"
                startHeaders    = "<div style='display:table-header-group;font-weight:bold'>"
                cell            = "<div style='display:table-cell;width:25%;font-family:courier;font-size:90%'>"
                row             = "<div style='display:table-row;'>"
                rowgroup        = "<div style='display:table-row-group;'>"
                end             = "</div>"
                output          = ""

                # - Start
                output += "<br/><b>Splunk Results Table<b><br/>"
                output += startTable
                # - Build Headers
                output += startHeaders

                for hdrs in headers:
                    output += "{}{}&nbsp;&nbsp;</div>".format(cell, hdrs)
                else:
                    output += end
                # - Build out rows and columns
                for event in tabledata:
                    output += rowgroup
                    for row in event.values():
                        output += "{}{}</div>".format(cell, row)
                    else:
                        output += end
                else:
                    output += end
                
                #End
                output += end
                output += "<br/>"
                return output
            except Exception as err:
                self.log.warn(err)

        def processQuery(incident):
            try:
                query = incident['__query']
                outText= "<div><b>Splunk Query</b><br/>"
                #Clean up the Query Output, wrap on the pipe |
                cnt = len(query.split("|"))
                for item in query.split("|"):
                    cnt-=1
                    outText+=item+"<br/>|" if cnt != 0 else item
                else:
                    outText+="<br/></div>"
                return outText
            except Exception as err:
                self.log.warn(err)

        try:
            #Step One - Create Incident ticket
            #URI to perform the initial creation of the incident ticket. 
            url     = "{0}/rest/orgs/{1}/incidents/".format(self.hostURI, self.orgid)
            #SeverityCodes - 56(High), 55(Medium), 54(Low)
            severityMap      = { "HIGH" : 56, "MEDIUM" : 55, "LOW" : 54}
            incidentTemplate = {
                                "name": incident['__alert'],
                                "discovered_date": int(incident['__timeutc']),
                                "description" : processDescription(incident),
                                "artifacts" : processArtifacts(incident, out='json'),
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

            try:
                #Step Two, Create a note w/ more details
                #Concat all the outputs to a note
                details = processDescription(incident)+processArtifacts(incident, out='html')+processQuery(incident)+processSpunkTable(incident)
                url = "{}/rest/orgs/{}/incidents/{}/comments".format(self.hostURI, self.orgid, incidentNumber)
                payload = json.dumps({"text" : { "format" : "html", "content" : details}})
                results = self.executeRequest('POST', url, data=payload)
                
            except KeyError as kerr:
                self.log.warn("Unable to add detials to ticket: {}".format(kerr))
                raise Exception("Ticket creation encountered issues when adding notes: {}".format(kerr))

            self.log.info("Added additional details to Incident ticket {} succesfully".format(incidentNumber))
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
            filename = qdir + filename
            #Write Events from Alert out to file
            json.dump(events, open(filename, 'wb+'), sort_keys=True, indent=2, separators=(',', ': '))
            self.log.debug('Dumped events to file: {}'.format(filename))
            return filename
        except Exception as err:
            self.log.war(err)

    def failureLoadEvents(self, count=None):
        """
            If we where unable to communicate with the Resilent ticketing system, we likely dumped alert events to a file.
            Look to see if any s2r_queued_<uuid>.json files exists in current directory, if so load them into a event Container.
            After succesful tranmition of events, remove the s2r_queued_ files from system
            If unsuccesful, leave files

            If count is True, returns count of queued events in queue files, then exits
        """
        lockaquired = False
        #Exit if we dont want to attempt recovery - sendonup == True in config file
        if not self.sendOnUp and not count:
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
        except Exception as err:
            self.log.warn(err)
        finally:
            #Ensure we remove the lock, incase there was an error
            if lockaquired: self.delLock()

    def failureSendEmail(self, events):
        """
            Process events into messages which can be sent to an email address.
            Sends text and html based messages
        """
        #Variables
        sender      = self.config.get('recovery', 'sender')
        recipient   = self.config.get('recovery', 'recipient')
        self.log.info("Sending events via Email")

        #Format Helpers
        def textBase(tmpHeaders, query, artifacts, evnts):
            """
                Handle Text Based Message formating for email
            """
            try:
                outText = ""
                outText+= "Splunk Generated Event\n"
                outText+= tabulate(tmpHeaders.iteritems(), tablefmt="plain", stralign="left")
                outText+= "\n\n"
                outText+= "Splunk Results Table\n"
                outText+= tabulate(evnts, headers="keys", tablefmt="plain", stralign="center")
                outText+= "\n\n"
                outText+= "Event Artifacts\n"
                outText+= tabulate(artifacts, tablefmt="plain", stralign="left")
                outText+= "\n\n"
                outText+= "Splunk Query\n"
                #Clean up the Query Output, wrap on the pipe |
                cnt = len(query.split("|"))
                for item in query.split("|"):
                    cnt-=1
                    outText+=item+"\n|" if cnt != 0 else item 
                else:
                    outText+= "\n\n"
                return outText
            except Exception as err:
                self.log.warn(err)

        def htmlBase(tmpHeaders, query, artifacts, evnts):
            """
                Handle HTML Based Message formating for email (This is the best way...)
            """
            try:
                outText = ""
                outText+= "<b>Splunk Generated Event</b>"
                outText+= tabulate(tmpHeaders.iteritems(), tablefmt="html", stralign="left")
                outText+= "<br clear=\"all\" style=\"page-break-before:always\" />"
                outText+= "<b>Splunk Results Table</b>"
                outText+= tabulate(evnts, headers="keys", tablefmt="html", stralign="center")
                outText+= "<br clear=\"all\" style=\"page-break-before:always\" />"
                outText+= "<b>Event Artifacts</b>"
                outText+= tabulate(artifacts, tablefmt="html", stralign="left")
                outText+= "<br clear=\"all\" style=\"page-break-before:always\" />"
                outText+= "<b>Splunk Query</b><br/>"
                #Clean up the Query Output, wrap on the pipe |
                cnt = len(query.split("|"))
                for item in query.split("|"):
                    cnt-=1
                    outText+=item+"<br/>|" if cnt != 0 else item 
                else:
                    outText+= "<br clear=\"all\" style=\"page-break-before:always\" /> <br/>"
                return outText
            except Exception as err:
                self.log.warn(err)

        try:        
            #If we have a large number of events > 10, add delay.
            isBulk = True if len(events) >= 10 else False
            if isBulk: self.log.info("Bulk number of events detected, adding delay per email")
            #Process events, then mail them out
            for xvnt in events:
                headers = [y for y in xvnt.keys() if not '__events' in y]
                tmpHeaders = collections.OrderedDict()
                tmpHeaders['Alert:']    = xvnt['__alert']
                tmpHeaders['Priority:']  = xvnt['__priority']
                tmpHeaders['Count:']    = xvnt['__count']
                #Perform Time translation to make it human readable
                timestamp = xvnt['__timeutc']
                utcTimeStamp = int(int(timestamp)/1000)
                dt = datetime.datetime.utcfromtimestamp(utcTimeStamp)
                displayString = "{}:{}:{} {}/{}/{}".format(dt.hour,dt.minute,dt.second,dt.month,dt.day,dt.year)
                tmpHeaders['Time UTC:']  = displayString
                ##
                tmpHeaders['Ehash:']    = xvnt['__ehash']
                tmpHeaders['Focus:']    = xvnt['__focus']
                #Clean up URL
                splunkurl   = xvnt['__url']
                idxHtml = str(splunkurl).index("__search__")+10
                tmpHeaders['Splunk Link:']  = "<a href='{}' target='_blank'>{}</a>".format(str(splunkurl), str(splunkurl)[idxHtml:])
                ##
                evnts       = xvnt['__events']
                #Enrich artifacts, transform int values to valid name values
                artCodes = {
                            1: "IP Address: ",
                            2: "DNS: ",
                            3: "URL: ",
                            4: "eMail: ",
                            13: "Malware MD5: ",
                            14: "Malware SHA1: ",
                            29: "String: "
                            }
                artifacts = [(artCodes[int(y)], x) for x,y in xvnt['__artifacts'].items()]
                ##
                query       = xvnt['__query']
                #Process Text for this event
                msgText = textBase(tmpHeaders, query, artifacts, evnts)
                msgHTML = htmlBase(tmpHeaders, query, artifacts, evnts)
                subject = "Splunk2Resilient: {}, failed to send to Resilent".format(xvnt['__alert'])
                #We send both HTML and TEXT formats, however HTML is preferred, as text is VERY hard to format
                self.mailer(recipient, sender, subject, txtmsg=msgText, htmlmsg=msgHTML)
                #Insert artificial delay of 0.5sec/email, if a LARGE number of emails are generated, we dont want to get locked out.
                if isBulk:
                    time.sleep(0.5)
        except Exception as err:
            self.log.critical(err)

    def getLock(self):
        """
            Attempts to create file /tmp/s2r.lck if it doesnt already exists.
            If it does exists, failed to get lock (likley already exists), returns False
                If lock exists, validate timestamp of lockfile is NOT OVER 90 seconds. If so, delete!
            If it doesnt exists, will create the file and return True
            Note this is done in one step via os.open to ensure we dont encounter a race condition

            Return True; lock aquired
            Return False; not aquired
        """
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            flock = os.open('/tmp/s2r.lck', flags)
            self.log.debug('Aquired lock @ /tmp/s2r.lck')
        except OSError as err:
            #Does the file already exists?
            if err.errno == errno.EEXIST:
                self.log.info('Unable to aquire lock, existing lock in place')
                #We are going to double check the locks timestamp is not over 60 seconds from current epoch
                #If so, we are going to blow it away, as its BAD (no lock should exist over 1 minute)
                with open('/tmp/s2r.lck', 'r') as lckfile:
                    oldEpoch = int(lckfile.read())
                    if int(time.time()) - oldEpoch >= 90:
                        self.log.warn('Attempting to remov old lock file, is over 90 seconds old')
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
            Attempts to delete lock file from /tmp/ directory
            Return True; File was deleted
            Return False; File was unable to be deleted
        """
        try:
            os.remove('/tmp/s2r.lck')
            self.log.debug('Deleted aquired lock @ /tmp/s2r.lck')
            return True
        except Exception as err:
            self.log.warn("Unable to remove lock file: {}".format(err))
            return False

    def mailer(self, recipient, sender, subject, txtmsg=None, htmlmsg=None):
        """
            Generic smtp email client
            Requires recipient / sender / subject
            Can send text or html messages (or both) via txtmsg and htmlmsg
            Returns True on send, otherwise False on error
        """
        try:
            # Create message container
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = recipient
            if txtmsg:
                msg.attach(MIMEText(txtmsg, 'plain'))
            if htmlmsg:
                msg.attach(MIMEText(htmlmsg, 'html'))
            #Send Message
            mailrelay = self.config.get('recovery', 'mailrelay')
            snd = smtplib.SMTP(mailrelay)
            snd.sendmail(sender, recipient, msg.as_string())
            snd.quit()
            self.log.info("Email sent to {} w/ subject of: '{}'".format(recipient, subject))
            return True
        except Exception as err:
            self.log.warn("Unable to send email: {}".format(err))
            return False

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

def helpdocument():
    print """Splunk2Resilient v0.5
Used to process Splunk alerts into Resilient ticket items.

Command Options:
    ./s2r.py --help
    ./s2r.py --check-queue
    ./s2r.py --process-queue
    ./s2r.py --test-connection

Normal usage:
    Configure Splunk to call this script when an alert triggers.
Alert data is then processed and sent to Resilient.

Splunk queuries with special column names are treated diffrently:

    "o_<example>"
        Names that start with "o_" are used as a focus, and groups are formed based on these.
        1 ticket per group of entries.

    "a_<example>"
        Names that start with "a_" are used to indicate these items are artifacts.

More Examples:
    o_hostname  a_src_ip    a_filehash oa_dst_ip    oa_emailaddress
    * You can only have one focus column per query, otherwise the focus is dropped and each line will be treated as its own event.

See README.txt for more information
"""

def main(args):
    # --- Splunk Event Processor --- #
    argLength = len(sys.argv)
    #Help Documentation
    if argLength == 1:
        helpdocument()
        sys.exit(0)

    #Option Processing
    if argLength == 2:
        command = sys.argv[1]
        if command == "--help": 
            helpdocument()
            sys.exit(0)

        if command == "--check-queue": 
            queueCount = EventPusher().failureLoadEvents(count=True)
            print "Events in queue: {}".format(queueCount)
            sys.exit(0)

        if command == "--process-queue": 
            eventpusher = EventPusher()
            eventpusher.connect()
            eventpusher.failureLoadEvents()
            sys.exit(0)

        if command == "--test-connection": 
            EventPusher().connect(test=True)
            sys.exit(0)

    #Splunk Processing
    if argLength == 9:
        # Gather Splunk event data as eventArgs
        eventArgs = {
                        "count" : sys.argv[1],
                        "terms" : sys.argv[2],
                        "query" : sys.argv[3],
                        "name" : sys.argv[4],
                        "trigger" : sys.argv[5],
                        "url" : sys.argv[6],
                        "file" : sys.argv[8]
                    }
        # Start Event Parser
        eventparser     = EventParser()
        #  -Unpack events
        unpackedEvents  = eventparser.unpackEvents(eventArgs)
        #  -Process events into workable segments, packed in a container (list)
        eventContainer  = eventparser.processEvents(unpackedEvents, eventArgs)
        # Start Event Pusher
        eventpusher     = EventPusher()
        #  -Connect to Resilient
        eventpusher.connect()
        #  -Attempt to send Event data to Resilient
        validate        = eventpusher.sendEvents(eventContainer)
        #  -Check for queued events, if validate == True, else pass on this step
        #  -Will not trigger if queuemsg is set to False in conf file.
        if validate:
            #Exit after attempt
            eventpusher.failureLoadEvents()
        sys.exit(0)

    #Catch all for invalid command line usage
    print "Please enter a valid command"
    helpdocument()
    sys.exit(0)

if __name__ == '__main__':
    #Init/Start Logger
    EventLogger()
    #Send event data to main
    main(sys.argv)