# log-analyzer
A very basic access log analyzer
USAGE: loganalyzer.sh <logfile> [ uri | method | hits | response | xfer | os ] 
TODO: diff of byte count requests for same resource, unusual User Agent info, redirect analysis, date time analysis, clean up and optimize code, change os option to ua

At this time the options will do the following:
* uri will list unusual requests
* response will list 403's and time-outs
* hits will count the number of times > 1 a resource was accessed
* method will list requests that were denied by the server and the number of methods that are != GET
* xfer will list top 10 talkers
* os counts the number of various user agent platforms used (incorrectly named for now)


This is a WIP!
