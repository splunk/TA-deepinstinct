from tracemalloc import start
import import_declare_test
import sys
import json
import os
import os.path as op
import time
from datetime import datetime
import traceback
import requests
from splunklib import modularinput as smi
from solnlib import conf_manager
from solnlib import log
from solnlib.modular_input import checkpointer


import re
#TODO remove this before deployment
sys.path.append(os.path.join('/opt/splunk','etc','apps','SA-VSCode','bin'))
import splunk_debug as dbg
dbg.enable_debugging(timeout=10)

MINIMAL_INTERVAL = 30
APP_NAME = __file__.split(op.sep)[-3]
CONF_NAME = "ta_deepinstinct"



def get_log_level(session_key, logger):
    """
    This function returns the log level for the addon from configuration file.
    :param session_key: session key for particular modular input.
    :return : log level configured in addon.
    """
    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))

        logging_details = settings_cfm.get_conf(
            CONF_NAME+"_settings").get("logging")

        log_level = logging_details.get('loglevel') if (
            logging_details.get('loglevel')) else 'INFO'
        return log_level

    except Exception:
        logger.error(
            "Failed to fetch the log details from the configuration taking INFO as default level.")
        return 'INFO'

def get_account_details(session_key, account_name, logger):
    """
    This function retrieves account details from addon configuration file.
    :param session_key: session key for particular modular input.
    :param account_name: account name configured in the addon.
    :param logger: provides logger of current input.
    :return : account details in form of a dictionary.    
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key, APP_NAME, realm='__REST_CREDENTIAL__#{}#configs/conf-{}_account'.format(APP_NAME,CONF_NAME))
        account_conf_file = cfm.get_conf(CONF_NAME + '_account')
        logger.info(f"Fetched configured account {account_name} details.")
        return {
            "accountname": account_name,
            "apihost": account_conf_file.get(account_name).get('apihost'),
            "apikey": account_conf_file.get(account_name).get('apikey'),
            "event_start": account_conf_file.get(account_name).get('event_start'),
            "sus_event_start": account_conf_file.get(account_name).get('sus_event_start')
        }
    except Exception as e:
        logger.error("Failed to fetch account details from configuration. {}".format(traceback.format_exc()))
        sys.exit(1)

def get_proxy_details(session_key, logger):
    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))
        proxy_details = settings_cfm.get_conf(CONF_NAME+"_settings").get("proxy")        
        logger.info(f"Fetched proxy details.")
        
        return proxy_details
    except Exception as e:
        logger.error("Failed to fetch proxy details from configuration. {}".format(traceback.format_exc()))
        sys.exit(1)



def get_starting_details(session_key, logger, accountDetails, lastEvent, lastSusEvent):
    try:
        eventStart = None
        susEventStart = None

        # try: 
        #     cfm = conf_manager.ConfManager(
        #         session_key, APP_NAME, realm='__REST_CREDENTIAL__#{}#configs/conf-{}_settings'.format(APP_NAME,CONF_NAME))
        #     startpoints_conf_file = cfm.get_conf(CONF_NAME + '_settings').get('startpoints')
        #     logger.info(f"Fetched event starting point defaults.")

        #     #get the starting points from the config file
        #     eventStart = int(startpoints_conf_file.get("event_start"))
        #     susEventStart = int(startpoints_conf_file.get("sus_event_start"))
        # except Exception as e:
        #     logger.info("there was no config entry for start points defined")


        try:
            eventStart = int(accountDetails.get("event_start"))
            susEventStart = int(accountDetails.get("sus_event_start"))
        except Exception as e:
            logger.info(e)

        #start with empty values for a starting point
        retVal = {"event_start": None, "sus_event_start": None}

        #set some defaults if they are blank
        if lastEvent == None: lastEvent = 0
        if eventStart == None: eventStart = 0

        # do a quick check to set the higher value if there is one.. (otherwise it will stay None)
        if lastEvent > eventStart:
            retVal["event_start"] = lastEvent
        if eventStart > lastEvent:
            retVal["event_start"] = eventStart

        # do the same for suspicious events
        if lastSusEvent == None: lastSusEvent = 0
        if susEventStart == None: susEventStart = 0

        if lastSusEvent > susEventStart:
            retVal["sus_event_start"] = lastSusEvent
        if susEventStart > lastSusEvent:
            retVal["sus_event_start"] = susEventStart


        return retVal

    except Exception as e:
        logger.error("Failed to fetch default event start details from configuration. {}".format(traceback.format_exc()))
        sys.exit(1)


def get_proxy_param(proxyDetails):
    try:
        useSocks = False
        if proxyDetails != None:
            if proxyDetails.get("proxy_enabled") == '1':
                proxyUsername = proxyDetails.get("proxy_username")
                proxyPassword = proxyDetails.get("proxy_password")
                if proxyUsername != None:
                    useSocks = True
                proxyUrl = proxyDetails.get("proxy_url")
                proxyPort = proxyDetails.get("proxy_port")

                if useSocks:
                    return {"https": "socks5://{}:{}@{}:{}".format(proxyUsername, proxyPassword, proxyUrl, proxyPort)}
                else:
                    return {"https": "https://{}:{}".format(proxyUrl, proxyPort)}
            else:
                return None
        else:
            return None
    except Exception as e:
        logger.error("Failed to get proxy parameters.")
        sys.exit(1)



def get_new_records(logger, ew, apiHost, apiKey, startingPoints, inputItems, endpoints, proxyParam):

    retVal = {"newEventCheckpoint":None, "newSusEventCheckpoint":None}

    for ep in endpoints.split("|"):
        nextEvent = None
        epSourceType = ep.lower() #create a lowercase version of the endpoint to use in the sourcetype
        
        epSourceType = re.sub("/", ":", epSourceType)
        epSourceType = re.sub("-", ":", epSourceType)

        if ep == "events" and "event_start" in startingPoints:
            nextEvent = startingPoints["event_start"]

        if ep == "suspicious-events" and "sus_event_start" in startingPoints:
            nextEvent = startingPoints["sus_event_start"]


        while True:
            getRecordsUrl = "https://{}/api/v1/{}".format(apiHost, ep)

            if nextEvent != None:
                if ep == "devices":
                    getRecordsUrl = "{}?after_device_id={}".format(getRecordsUrl, nextEvent)
                else:
                    getRecordsUrl = "{}?after_event_id={}".format(getRecordsUrl, nextEvent)

            getRecordsHeaders = {
                "Accept": "application/json",
                "Authorization": apiKey
            }

            if proxyParam == None:
                recordsResponse = requests.get(url=getRecordsUrl, headers=getRecordsHeaders, timeout=(10.0,30.0))
            else:
                recordsResponse = requests.get(url=getRecordsUrl, headers=getRecordsHeaders, timeout=(10.0,30.0), proxies=proxyParam)

            recordsResponseStatus = recordsResponse.status_code
            if recordsResponseStatus != 200:
                logger.debug("Get records returned non-200 status code: {}".format(recordsResponseStatus))
                recordsResponse.raise_for_status()

            getRecordsJSON = recordsResponse.json()

            if "last_id" in getRecordsJSON:
                if getRecordsJSON["last_id"] != None:
                    nextEvent = getRecordsJSON["last_id"] 


            if "events" in getRecordsJSON:
                logger.info("found events in record, sending individually with timestamp")
                for record in getRecordsJSON["events"]:
                    recordEvent = smi.Event()
                    recordEvent.data = json.dumps(record)
                    recordEvent.index = inputItems.get("index")
                    recordEvent.sourceType = "deepinstinct:operational:{}".format(epSourceType)
                    recordEvent.done = True
                    recordEvent.unbroken = True
                    recordEvent.time = datetime.strptime(record["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()                    
                    ew.write_event(recordEvent)
            elif "devices" in getRecordsJSON:
                logger.info("found devices in record, sending individually with timestamp")
                for record in getRecordsJSON["devices"]:
                    recordEvent = smi.Event()
                    recordEvent.data = json.dumps(record)
                    recordEvent.index = inputItems.get("index")
                    recordEvent.sourceType = "deepinstinct:operational:{}".format(epSourceType)
                    recordEvent.done = True
                    recordEvent.unbroken = True
                    recordEvent.time = time.time()
                    ew.write_event(recordEvent)
            else:
                logger.info("no event data, sending data as a chunk")
                recordEvent = smi.Event()
                recordEvent.data = json.dumps(getRecordsJSON)
                recordEvent.index = inputItems.get("index")
                recordEvent.sourceType = "deepinstinct:operational:{}".format(epSourceType)
                recordEvent.done = True
                recordEvent.unbroken = True
                recordEvent.time = time.time()
                
                ew.write_event(recordEvent)

            if "last_id" not in getRecordsJSON:
                break

            if "last_id" in getRecordsJSON and getRecordsJSON["last_id"] == None:
                break
        
        if ep == "events" and nextEvent != startingPoints["event_start"]:
            retVal["newEventCheckpoint"] = nextEvent

        if ep == "suspicious-events" and nextEvent != startingPoints["sus_event_start"]:
            retVal["newSusEventCheckpoint"] = nextEvent
    
    return retVal
        


class CVAD_OPERATIONAL(smi.Script):

    def __init__(self):
        super(CVAD_OPERATIONAL, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('deepinstinct_operational')
        scheme.description = 'Deep Instinct Operational'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        
        
        scheme.add_argument(
            smi.Argument(
                'endpoints',
                required_on_create=True,
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'account',
                required_on_create=True,
            )
        )
        
        return scheme

    def validate_input(self, definition):
        return

    def stream_events(self, inputs, ew):
        metaConfigs = self._input_definition.metadata
        sessionKey = metaConfigs['session_key']
        inputName = list(inputs.inputs.keys())[0]

        inputItems = {}
        inputItems = inputs.inputs[inputName]

        # Generate logger with input name
        _, inputName = (inputName.split('//', 2))
        logger = log.Logs().get_logger('{}_input'.format(APP_NAME))

        # Log level configuration
        logLevel = get_log_level(sessionKey, logger)
        logger.setLevel(logLevel)        

        logger.debug("Modular input invoked.")

        lastEventKey = "{}_{}".format(inputName, 'lastevent')
        lastSusEventKey = "{}_{}".format(inputName, 'lastsusevent')

        eventCheckpoint = checkpointer.KVStoreCheckpointer("last_events", sessionKey, APP_NAME)
        lastEventCheckpoint = eventCheckpoint.get(lastEventKey)
        lastSusEventCheckpoint = eventCheckpoint.get(lastSusEventKey)

        # get the account name to do the data pull for
        accountName = inputItems.get('account')
        accountDetails = get_account_details(sessionKey, accountName, logger)        
        apiHost = accountDetails.get("apihost")
        apiKey = accountDetails.get("apikey")

        # get starting point data (taking into account the checkpoint values)
        startingPoints = get_starting_details(sessionKey, logger, accountDetails, lastEventCheckpoint, lastSusEventCheckpoint)




        # get proxy details
        proxyDetails = get_proxy_details(sessionKey, logger)
        proxyParam = get_proxy_param(proxyDetails)

        endpointData = inputItems.get("endpoints")


        new_checkpoints = get_new_records(logger, ew, apiHost, apiKey, startingPoints, inputItems, endpointData, proxyParam)

        if new_checkpoints["newEventCheckpoint"] != None:
            logger.info(f"Updating last event checkpoint")
            eventCheckpoint.update(lastEventKey, new_checkpoints["newEventCheckpoint"])

        if new_checkpoints["newSusEventCheckpoint"] != None:
            logger.info(f"Updating last sus event checkpoint")
            eventCheckpoint.update(lastSusEventKey, new_checkpoints["newSusEventCheckpoint"])



if __name__ == '__main__':
    exit_code = CVAD_OPERATIONAL().run(sys.argv)
    sys.exit(exit_code)