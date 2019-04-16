import json
import datetime
from java.io import PrintWriter
from burp import IBurpExtender, IBurpExtenderCallbacks, ISessionHandlingAction, IHttpRequestResponse


class BurpExtender(IBurpExtender, ISessionHandlingAction):
    AUTH_HEADER_PREFIX = 'Authorization: '
    NAME = "Bearer Authorization Token"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.getActionName()) 
        self.callbacks.registerSessionHandlingAction(self)    
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.pluginInitOutput()
        return
    
    def pluginInitOutput(self):
        self.stdout.println("Bearer Authorization Token \n")
        self.stdout.println('starting at time : {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        self.stdout.println("-----------------------------------------------------------------\n\n")

    def getActionName(self):
        return self.NAME
     
    def performAction(self, currentRequest, macroItems):
        #Extract the Bearer token from the macro response
        try:
            request_info = self.helpers.analyzeRequest(currentRequest)
            macro_response_info = self.helpers.analyzeResponse(macroItems[0].getResponse())
            bearer = self.get_bearer_token(macroItems, macro_response_info)
            self.handle_bearer_updates(request_info, currentRequest, macro_response_info, bearer)
        except Exception as e:
            self.printPluginError(e)
        return

    def handle_bearer_updates(self, request_info, currentRequest, macro_response_info, bearer):
        try:
            headers = request_info.getHeaders()
            req_body = currentRequest.getRequest()[request_info.getBodyOffset():]
            resp_headers = macro_response_info.getHeaders()  
            headers = request_info.getHeaders()
            if self.findAndRemoveAuthHeader(headers):
                headers.add('{}{}'.format(self.AUTH_HEADER_PREFIX, bearer))
                self.printPluginOutput(bearer)

                # Build request with bypass headers        
                message = self.helpers.buildHttpMessage(headers, req_body)        
                # Update Request with New Header        
                currentRequest.setRequest(message)
            else:
                self.printPluginError()
        except Exception as e:
            self.printPluginError(e)
        return None

    def get_bearer_token(self, macroItems, macro_response_info):
        try:
            macro_msg = macroItems[0].getResponse()
            resp_body = macro_msg[macro_response_info.getBodyOffset():]
            macro_body_string = self.helpers.bytesToString(resp_body)
            bearer = macro_body_string[1:len(macro_body_string) - 1]
            return bearer
        except Exception as e:
            self.printPluginError(e)
        return None
    
    def printPluginError(self, e = ''):
        self.stdout.println('*** Error occurred during plugin execution ***')
        if e != '':
            self.stdout.println(e)
            self.stdout.println('**********************************************')

    def performAction(self, currentRequest, macroItems):
        try:
            request_info = self.helpers.analyzeRequest(currentRequest)
            macro_response_items = self.helpers.analyzeResponse(macroItems[0].getResponse())
            bearer = self.get_bearer_token(macroItems, macro_response_items)
            self.handle_bearer_updates(request_info, currentRequest, macro_response_items, bearer)
        except Exception as e:
            self.printPluginError(e)

    def findAndRemoveAuthHeader(self, headers):
        auth_to_delete = ''
        for head in headers:
            if self.AUTH_HEADER_PREFIX in head:
                auth_to_delete = head        
        try:
            headers.remove(auth_to_delete)
            return True
        except:
            pass
        if auth_to_delete == '':
            return True
        return None
    
    def printPluginOutput(self, bearer):
        self.stdout.println('Header Checked at time :  {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))        
        self.stdout.println("-----------------------------------------------------------------"        )
        self.stdout.println("Adding new header - {} {}".format(self.AUTH_HEADER_PREFIX, bearer))
        self.stdout.println("-----------------------------------------------------------------")                
        self.stdout.println("Geting authorized..done\n\n")                