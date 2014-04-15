#-------------------------------------------------------------------------------
# Name:        VTsubmissionTool
# Purpose:     Used to submit hashes or files to VirusTotal and retrieve results
#              System accepts HTTP POSTS and responds with JSON
#
# Author:      stormrainer
#
# Created:     24/12/2012
# Updated:     08/04/2013 for domain and IP reports
#-------------------------------------------------------------------------------
import urllib
import urllib2
import json
import time
import hashlib
import sys, os
from optparse import OptionParser

SITE_TO_SEND_FILE = "https://www.virustotal.com/vtapi/v2/file/scan"
SITE_TO_REQ_FILE_RESCAN = "https://www.virustotal.com/vtapi/v2/file/rescan"
SITE_TO_RET_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/report"
SITE_TO_REQ_URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/scan"
SITE_TO_RET_URL = "https://www.virustotal.com/vtapi/v2/url/report"
SITE_TO_RET_DOMAIN ="https://www.virustotal.com/vtapi/v2/domain/report"
SITE_TO_RET_IP = "http://www.virustotal.com/vtapi/v2/ip-address/report"

def Usage():
    print 'Usage: python VTsubmissionTool.py APIKEY'


# API KEY is limited to four(4) requests per minute
API_KEY = "yourkeyhere"
REQUEST_LIMIT = 4
#FileSizeLimit = 33554432    # 32 MB
FileSizeLimit = 67108864 #64 MB (new file size limit) 04/08/2013
# HASH FUNCTIONS #

def md5sum(filename):
    md5 = hashlib.md5()
    try:
        with open(filename, 'r+b') as f:
            for chunk in iter(lambda: f.read(128*md5.block_size), b''):
                md5.update(chunk)
        f.close()
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except:
        print "we didnt find gold"
    print md5.hexdigest()
    return md5.hexdigest()

def sha1(filename):
    try:
        f = open(filename, 'r+b')
        data = f.read()
        sha1 = hashlib.sha(data).hexdigest()
        f.close
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except Exception, msg:
        print msg
    return sha1

def sha256(filename):
    try:
        f = open(filename, 'r+b')
        data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        f.close()
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except Exception, msg:
        print msg
    return sha256

# Virus Total Functions

def req_file_scan(f):

    return json

# resource can be md5, sha1, or sha256 hashes
def req_file_rescan(hash):
    parameters = {"resource": hash,
                  "apikey": API_KEY}
    data = urllib.urlencode(parameters)
    request = urllib2.Request(SITE_TO_REQ_FILE_RESCAN, data)
    response = urllib2.urlopen(request)
    json = response.read()
    return json

# can have up to 25 hashes
def ret_file_scan(f):
    # optional parameters to send for scan, use scan: 1
    parameters = {"resource": f,
                  "apikey": API_KEY}
    data = urllib.urlencode(parameters)
    request = urllib2.Request(SITE_TO_RET_FILE_SCAN, data)
    response = urllib2.urlopen(request)
    json = response.read()
    return json

def ret_url_report(urlToScan):
    parameters = {"resource": urlToScan,
                  "scan": 1,
                  "apikey": API_KEY}
    data = urllib.urlencode(parameters)
    request = urllib2.Request(SITE_TO_RET_URL, data)
    response = urllib2.urlopen(request)
    json = response.read()
    return json

#something is not working as expected. Had to manually submit the url
def submit_url():
    parameters = {"resource": urlToScan,
                  "apikey": API_KEY}
    data = urllib.urlencode(parameters)
    request = urllib2.Request(SITE_TO_REQ_URL_SCAN, data)
    response = urllib2.urlopen(request)
    json = response.read()
    return json

#need to add ways to handle response codes for URL submissions.
# for instance, if response code is 0, we need to submit the URL for scanning
# if response code is 1, then we need to print out the report

def getDomainReport(domainToCheck):
    parameters = {"domain": domainToCheck,
                  "apikey": API_KEY}
    data = urllib.urlencode(parameters)
    response = urllib.urlopen('%s?%s' % (SITE_TO_RET_DOMAIN, data)).read()
    response_dict = json.loads(response)
    print response_dict

def getIPReport(ipAddress):
    parameters = {"ip": ipAddress,
                  "apikey": API_KEY}
    data = urllib.urlencode(parameters)
    response = urllib.urlopen('%s?%s' % (SITE_TO_RET_IP, data)).read()
    response_dict = json.loads(response)
    print response_dict

class SizeLimitException(Exception):
    def _init_(self, message, Errors):
        Exception.__init__(self, message)
        self.message

# Whenever you exceed the public API request rate limit a 204 HTTP status code is returned
class RateLimitException(Exception):
    def _init_(self, message, Errors):
        Exception.__init__(self, message)
        self.message

def malwr(f):
    url = 'http://malwr.com/analysis/' + md5sum(f) + '/'
    try:
        send = urllib2.urlopen(url).read()
        for line in send.split('\n'):
            if line.find("Malwr - Analysis") == 1:
                return "Matching report in Malwr database"
            else:
                return "No match found in Malwr database"
    except:
        return "Error"

def main():
    #submit_url()
    #time.sleep(30)
    #try:
    #    results(ret_url_report("http://brospecial.net/annihilates/index.html"))
    #except RateLimitException:
    #    print 'you have exceeded rate per minute'
    #    raise
    #pass
    #parser = OptionParser()
    #(options,args) = parser.parse_args()
    try:
        #for domain in args:
        #    getDomainReport(domain)
        #ret_file_scan("C:\Users\dfs\Documents\949488.pdf")
        #possible response codes include -1,0,1  1<- report found 0 domain not found (may need to lower-case everything
        getDomainReport("dhuaa.no-ip.org")
        #print(ret_url_report("http://www.federicahome.it/ideologically/index.html"))
        #getIPReport("23.19.122.202")
        #If VirusTotal has absolutely no information regarding the IP address under consideration, the JSON's response code will be 0, -1 if the submitted IP address is invalid.
    except RateLimitException:
        print 'you have exceeded rate per minute'
        raise
    pass

if __name__ == '__main__':
    main()
