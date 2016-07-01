#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike & Chris Clark ~ GD Fidelis CyberSecurity


import json, urllib, urllib2, argparse, hashlib, re, sys, csv
from pprint import pprint

class vtAPI():
    def __init__(self):
        self.api = '51ac70976e31b552016385128cb3a6356252065b42f60b2f1a94d7b8932d87df'
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata = json.loads(result.read())
        return jdata

    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"

    def getUrlReport(self,URL):
        param = {'resource':URL,'apikey':self.api}
        url = self.base + "url/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url, data)
        jdata = json.loads(result.read())
        return jdata

    def getIPReport(self,IP):
        param = {'ip':IP,'apikey':self.api}
        url = self.base + "ip-address/report"
        data = urllib.urlencode(param)
        response = urllib.urlopen('%s?%s' % (url, data)).read()
        jdata = json.loads(response)
        return jdata



#======== MD5 FUNCTION =========

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else:
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest()

def parse(it, md5, verbose, jsondump):
  if it['response_code'] == 0:
    print md5 + " -- Not Found in VT"
    return 0
  print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n'

  #if 'Sophos' in it['scans']:
    #print '\tSophos Detection:',it['scans']['Sophos']['result'],'\n'

  # Quick view prints only in cases where the hash returns as true.

  print '\n\tQuick View:\n'

  for x in it['scans']:
    if it['scans'][x]['detected'] == True:
        print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

  print '\tScanned on:',it['scan_date'], '\n'

  if jsondump == True:
    jsondumpfile = open("VTDL" + md5 + ".json", "w")
    pprint(it, jsondumpfile)
    jsondumpfile.close()
    print "\n\tJSON Written to File -- " + "VTDL" + md5 + ".json"


  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']


#============END of MD5 FUNCTION======================


#======== URL FUNCTION =========

def parseURL(it, url, verbose, jsondump):
    if it['response_code'] == 0:
        print url + " -- Not Found in VT"
        return 0
    print "\n\tResults for URL: ",it['url'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n'

    print '\n\tQuick View:\n'

    for x in it['scans']:
        if it['scans'][x]['detected'] == True:
            print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

    print '\n\tScanned on:',it['scan_date'], '\n'

    if jsondump == True:
        jsondumpfile = open("VTDL" + url + ".json", "w")
        pprint(it, jsondumpfile)
        jsondumpfile.close()
        print "\n\tJSON Written to File -- " + "VTDL" + url + ".json"

    if verbose == True:
        print '\n\tVerbose VirusTotal Information Output:\n'
        for x in it['scans']:
            print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

#============END of URL FUNCTION======================

#======== IP FUNCTION =========

def parseIP(it, IP):
    if it['response_code'] == 0:
        print IP + " -- Not Found in VT"
        return 0

    print "\n\tResults for IP:",IP,"\n"

    print "\t====Passive DNS Info:====\n"
    print "\t\t%-24s%s" % ("Last Resolved","Hostname")
    for x in it["resolutions"]:
        print "\t\t%-24s%s" % (x["last_resolved"],x["hostname"])

    if "undetected_downloaded_samples" in IP:
        print "\n\t====Undetected Downloaded Samples====\n"
        print "\t\t%-13s %-20s %-19s" % ("Detections","Scan Date","sha256")
        for x in IP["undetected_downloaded_samples"]:
            print "\t\t%d / %-9d %-20s %s" % (x["positives"],x["total"],x["date"],x["sha256"])



    if "detected_urls" in it:
        TPositives = 0.0
        TTotal = 0.0
        Chance = 0.0
        print "\n\t====Detected URLs====\n"
        print "\t%-13s %-13s %-20s %-19s" % ("Chance","Detections","Scan Date","URL")
        for x in it["detected_urls"]:
            num1 = int(x["positives"])
            num2 = int(x["total"])
            Chance = ((float(num1))/(float(num2)))*100
            print "\t%-9d %-6d / %-9d %-20s %s" % (Chance, x["positives"],x["total"],x["scan_date"],x["url"],)
        print
        

#============END of IP FUNCTION======================

#======== OPEN IP CSV LIST FUNCTION =========

def parseCSVIP(FileName):
    file = open(FileName)
    csv_file = csv.reader(file)

    for row in csv_file:
        print row




#============END of IP CSV LIST FUNCTION======================

def main():
    opt=argparse.ArgumentParser(description="Search and Download from VirusTotal")
    opt.add_argument("arg", help="Enter the MD5/SHA1/256 Hash or Path to File")
    opt.add_argument("-s", "--search", action="store_true", help="Search Hash")
    opt.add_argument("-u", "--url", action="store_true", dest="url", help="Search URL")
    opt.add_argument("-i", "--ip", action="store_true", dest="ip", help="Search IP Address")
    opt.add_argument("-c", "--csvIP", action="store_true", dest="csvIP", help="Open a CSV file with a list of IP's")
    opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
    opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")
    opt.add_argument("-r", "--rescan",action="store_true", help="Force Rescan with Current A/V Definitions")

    if len(sys.argv)<=2:
        opt.print_help()
        sys.exit(1)

    options = opt.parse_args()
    vt=vtAPI()

    if options.search or (options.search and options.jsondump) or (options.search and options.verbose):
        md5 = checkMD5(options.arg)
        parse(vt.getReport(md5), md5, options.verbose, options.jsondump)
    if options.url or (options.url and options.jsondump) or (options.url and options.verbose):
        URL = options.arg
        parseURL(vt.getUrlReport(URL), URL, options.verbose, options.jsondump)
    if options.ip:
        IP = options.arg
        parseIP(vt.getIPReport(IP), IP)
    if options.csvIP:
        FileName = options.arg
        parseCSVIP(FileName)
    if options.rescan:
        vt.rescan(md5)

if __name__ == '__main__':
    main()