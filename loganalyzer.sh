#!/bin/bash
##################################################################################
# Script Name: loganalyzer.sh                                                    #
# Author: Alicia Smith                                                           #
# Date: October 19th, 2015                                                       #
# Purpose: Coding challenge at the request of Mozilla                            #
# Rev: 0.16                                                                       #
# USAGE: loganalyzer.sh <logfile> [ uri | method | hits | response | xfer | os ] #
# To Be Added: diff of byte count requests for same resource, unusual User Agent #
# info, redirect analysis, date time analysis, clean up and optimize code        #
##################################################################################
set -e
#####################
# V A R I A B L E S #
#####################
tmp=/tmp
newfile=$(mktemp   "reformatted.XXXXX")
sortedips=$(mktemp "sortedips.XXXXX")
minlist=$(mktemp   "min-list.XXXXX")
dates=$(mktemp     "date.XXXXX")
totalbytes=$(mktemp   "bytes.XXXXX")
onlyips=$(mktemp "onlyips.XXXXX")
uris=$(mktemp      "uri.XXXXX")
sorteddate=$(mktemp   "sorteddate.XXXXX")
suspect=$(mktemp   "suspecturis.XXXXX")
transfers=$(mktemp "transfers.XXXXX")
transferred=$(mktemp   "transferred.XXXXX")
transferredb=$(mktemp  "transferredb.XXXXX")
xfersortedbyuri=$(mktemp   "xfersortedbyuri.XXXXX")
useragents=$(mktemp    "useragent.XXXXX")
tmpfiles=("$newfile" "$minlist" "$dates" "$totalbytes" "$uris" "$sorteddate" "$transfers" "$transferred" "$transferredb" "$xfersortedbyuri" "$suspect" "$useragents" "$onlyips" "$sortedips")
file=$1
bold=$(tput bold)
cyan=$(tput setf 3)
normal=$(tput sgr0)
reqmethod=(CONNECT POST GET HEAD CONNECT PUT DELETE TRACE)

# linebreak function so I don't have to repeat the ugly dashed line.
linebreak() {
  printf "==========================================================================================\n"
}
  clear
  linebreak

function cleanUp() {
  for i in ${tmpfiles[@]}
  do
    if [[ -f "${i}" ]]
    then
      rm -r "${i}"
    fi
  done
  find . -maxdepth 1 -iname "*.txt" -type f -exec rm -f {} \;
}

trap cleanUp EXIT

#####################
# reformat log into #
# something we can  #
# work with         #
#####################
reformat(){
  sed -e 's/- - //g' -e 's/"/!/g' -e 's/\[//g' -e 's/\]//g' -e 's/\([0-9]\)\s\([0-9]\)/\1!\2/g' -e 's/compatible;//g' -e 's/Intel Mac OS X /Intel_Mac_OSX/g' -e 's/\(Windows\) \(NT\) /\1_\2_/g' -e 's/ !/!/g' -e 's/! /!/g' -e 's/!!/!/g' -e 's/;!/_/g' -e 's/[(]!/(/g' -e 's/\([0-9]\) \+/\1!/g'  -e 's/%/%%/g' -e 's/!-!/!NULL!/g' -e 's/-!/NULL!/g' "$file" >> "$newfile"
}


##############################
# read newfile into an array #
##############################
logarray() {
  while IFS=! read -r ip date tz request response bytes referrer useragent; do
    echo "${ip}" "${request}" "${response}" >> $minlist
                echo "${useragent}" >> $useragents
                echo "${date}" >> $dates
                echo "${ip}" "${date}" "${request}" "${response}" "${bytes}" "${referrer}" >> $totalbytes
        done < "$newfile"
}


log(){
    [ ! -z "${debug}" ] && echo "$*"
}

###########################################
# function to display the various number  #
# of platforms accessing the Server.      #
###########################################
countOS() {
  printf "${cyan}The following number of unique systems and their platform were detected${normal}\n"
  uas=(win_ua and_ua lin_ua iph_ua bla_ua bot_ua mac_ua)
  for file in "${uas[@]}"
     do
             cat ${file}.txt | sort | uniq -c > ${file}gent.txt
  done
  wc=$(grep -c "Windows" win_uagent.txt)
  lc=$(grep -c "Linux" lin_uagent.txt)
  ac=$(grep -c "Android" and_uagent.txt)
  bc=$(grep -c "BlackBerry" bla_uagent.txt)
  ic=$(grep -c "iPhone" iph_uagent.txt)
  botc=$(grep -c "[Bb]ot\|[Ss]pider\|Crawler\|Feed\|Yahoo" bot_uagent.txt)
  mc=$(grep -c "Mac" mac_uagent.txt)

  echo " Windows    : "${wc}" "
  echo " Linux      : "${lc}" "
  echo " Android    : "${ac}" "
  echo " BlackBerry : "${bc}" "
  echo " iPhone     : "${ic}" "
  echo " Bots       : "${botc}" "
  echo " Macintosh  : "${mc}" "
}

#####################################
# cleanup, reformat, and make array #
#####################################
reformat
logarray

########################################
# sort and grab number of hits, unique #
# ips, method, response, and uri       #
########################################
if [ -e $minlist ]
  then
    cat $minlist | sort | uniq -c >> $sortedips
  else
  printf "The $minlist file was not found.\n"

fi

########################################
# sort by date and grab beginning and  #
# ending dates                         #
########################################
if [ -e $dates ]
    then
      sort -k 1 $dates > $sorteddate
      day1=$(head -n 1 $sorteddate)
      lastday=$(tail -n1 $sorteddate)
      printf "This log begins on "${day1}" and ends on "${lastday}".\n"
    else
      printf "The $dates file was not found.\n"
fi

  linebreak

##########################################
# grab and sort bytes transferred        #
# date, ips, method, response, and uri   #
##########################################

if [ -e $totalbytes ]
  then
    for i in `cat $totalbytes |awk '{print $1}' |sort -u`
      do
        grep $i $totalbytes | awk '{c+=$5}END{print $1,$3,$4,c,$6}' >> $transfers
      done
      sort -rn $transfers -k4 >> $transferred
      head $transferred >> $transferredb
    else
      printf " The $totalbytes file was not found.\n"
fi

series200(){
  format="| %2s | %15s | %8s | %9s | %7s\n"
  if [[ "${response}" != - && "${response}" -ge 200 &&  "${response}" -le 250 ]]
    then
      printf "$format" "$hits" "$ip" "$method" "$response" "$uri"

  fi
}

series403(){
  format="| %2s | %15s | %8s | %10s | %s\n"
  if [[ "${response}" != - && "${response}" = 403 ]]
    then
      printf "$format" "$hits" "$ip" "$method" "$response" "$uri"
  fi
}

timedOut() {
format="| %2s | %15s | %8s | %10s | %s\n"
  if [ "${uri}" = 408 ]
    then
      printf "$format" "$hits" "$ip" "$method" "$response" "$uri"
  fi
}

getSuspectUri(){
  if echo "${uri}" | grep -qE '[^a-zA-Z0-9_\?\/\.\=\&-]'
    then
                        echo "${ip}" >> $onlyips
                        echo "${hits}" "${ip}" "${uri}" "${method}" >> $suspect
        fi
}

#printSuspectUri() {
#       while read -r
#}

getInfoOfUri() {
  gawk 'BEGIN{print "begin"}{print}END{print "end\n"}' "${onlyips}" >  ip.txt
  netcat whois.cymru.com 43 < $onlyips | sort -n >> results.txt
  sed -i '/AS Name/d' results.txt
  if [ -e results.txt ]
    then
      sed -i -e 's/\(\.\)\, /\1/g' -e 's/\([a-z\.\,]\) \([A-Za-z]\)/\1_\2/g' -e 's/\(\.\) \([A-Za-z]\)/\1_\2/g' results.txt
                        sed -i -e 's/,/ /g' results.txt
      sort -k 2 "$suspect" > sortedsuspect.txt
      sort -k 2 "results.txt" > sortedresults.txt
      awk '{getline f1 <"sortedsuspect.txt"; print f1, $1 " "$5" "$6 $7 $8 $9 $10 $11 $12 $13" "$14}' < sortedresults.txt > suspecturifinal.txt
  fi
}

reLoaded(){
  format="| %4s | %15s | %8s | %10s | %s\n"
  if [ "$hits" -gt 1 ]
            then
      printf "$format" "$hits" "$ip" "$method" "$response" "$uri"
  fi
}

noSuccess(){
  format="| %4s | %15s | %8s | %8s | %10s | %s\n"
    if [ "$response" != - ] && [ "$method" != GET ]
      then
        printf "$format" "$hits" "$ip" "$method" "$response" "$uri"
  fi
}

diffBytes(){
  format=" %2s %15s %8s %8s %18s\n"
        sort -u $totalbytes -k6 > $xfersortedbyuri
        awk -FS=" " '{
                prev=$0; f4=$4; f5=$5; f6=$6;
    getline
    if ( $4 == f4 && $5 != f5 && $6 == f6 ){
        print prev
                                print $0 >> "testfile.bak"

    }
        }' $xfersortedbyuri
   #   then
 #    printf "| %4s | %15s | %8s | %10s | %s \n" "$ip" "$method" "$response" "$bytes" "$uri"
#       fi
}

########################
# Table for displaying #
# Response Code 403    #
########################
table403() {
  printf "${cyan}The following accesses resulted in a 403 response code. \n${normal}"
  grep 403 $sortedips >> 403_requests.txt
  rc=$(awk 'END { print s } { s += $1 }' 403_requests.txt)
  printf "There are ${bold}$rc${normal} counts of the ${bold}403: Forbidden${normal} response code. The server has denied access to the resource. \n"
  printf "${bold}| Hits | IP %13s| Method %1s | Response %2s| %s URI ${normal}\n"
  while read -r hits ip method response uri;
    do
      series403
    done < $sortedips
}

#########################
# Table for displaying  #
# Suspect URI's & WHOIS #
#########################
tableSuspectUri() {
  printf "${cyan}Access to the following suspect uri's were attempted. Their ASN, ISP, and Country Code is appended.${normal}\n"
  printf "${bold}| Hits | IP %13s| Method %1s | URI %39s | Response %8s | %s WHOIS  ASN     |  ISP,CC${normal}\n"
  while read -r hits ip method uri http_ver response;
    do
      getSuspectUri
    done < $sortedips
        getInfoOfUri

}

###########################
# Table for displaying    #
# Requests that timed out #
###########################
tableTimeOut() {
  printf "${cyan}The following requests timed out.\n${normal}"
  printf "${bold}| Hits | IP %13s| Method %1s | Response %2s| %s URI ${normal}\n"
  while read -r hits ip method response uri;
    do
      timedOut
    done < $sortedips
}

################################
# Table for displaying IPs     #
# requesting the same resource #
################################
tableReLoaded() {
  printf "${cyan}The following IPs have more than ${bold}1${cyan} hit to the same resource. \n${normal}"
  printf "${bold}| Hits | IP %13s| Method %1s | Response %2s| %s URI ${normal}\n"
  while read -r hits ip method response uri;
    do
      reLoaded
    done < $sortedips
}

################################
# Table for displaying IPs     #
# requesting the same resource #
################################
tableNoSuccess() {
  printf "${cyan}The following accesses used a method other than GET.\n${normal}"
  printf "${bold}| Hits | IP %13s| Method %1s | Response %2s| %s URI ${normal}\n"
  while read -r hits ip method response uri;
    do
      noSuccess
    done < $sortedips
}

###############################
# Table for displaying method #
# count                       #
###############################
tableCountMethods() {
  printf "${cyan}Methods used within this log${normal}\n"
  for i in "${reqmethod[@]}"
    do
      printf "${bold}"$(grep -c $i $sortedips)"${normal} counts of ${bold}$i${normal} request method. \n"
    done
}

################################
# Table for displaying top     #
# talkers                      #
################################
tableTopTalkers() {
  printf "${cyan}The following are the top 10 cumulative totals of bytes transferred per unique IP \n${normal}"
  printf "${bold}| IP %13s| Method %s | Response %s| %s Total Bytes | URI %s${normal}\n"
  while read -r ip method response bytes uri;
    do
      printf "| %15s | %7s | %8s | %12s | %20s \n" "$ip" "$method" "$response" "$bytes" "$uri"
    done < $transferredb
}

##################################
# Table for displaying anomalous #
# bytecounts for same request    #
##################################
tableDiffBytes() {
  printf "${cyan}The following are similar requests that resulted in anomalous bytecounts\n${normal}"
  printf "${cyan} Please note it is not known which is correct, or if these are truly anomalies.\n${normal}"
  printf "${bold}| IP %13s| Method %s | Response %s| %s Total Bytes | URI %s ${normal}\n"
        diffBytes
}


displaystats() {
  for terms in "$@"
    do
    case $terms in
      uri)
                tableSuspectUri
                linebreak
         ;;
      response)
                table403
                linebreak
                tableTimeOut
                linebreak
         ;;
      hits)
                tableReLoaded
                linebreak
         ;;
    method)
                tableNoSuccess
                linebreak
                tableCountMethods
                linebreak
         ;;
      xfer)
                tableTopTalkers
                linebreak
        #                                                       tableDiffBytes # Not accurate yet so disabled.
         ;;
      os)
      countOS
        ;;
      *)
        printf "${cyan}That option is not known.${normal}\n"
        printf "${cyan}USAGE: loganalyzer.sh <logfile> [ uri | method | hits | response | xfer | os ]${normal}\n"

    esac
  done
}
# Call main function with case.
shift
displaystats $@


# We succeeded, reset trap and clean up normally.
trap - EXIT
cleanUp
exit 0
