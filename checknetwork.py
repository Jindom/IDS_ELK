 #!/usr/bin/env python3

import requests
import os
import time
import datetime
import re
import json
import operator
from sendsms import SendSMS


flagip={}
flagport={}
flagsourceip={}
flaghostname={}

def main():
	while True:
		checkfile(url)


def make_post_dict(post_time):
	data = {
	  "aggs": {
	    "2": {
	      "terms": {
	        "field": "@timestamp",
	        "order": {
	          "_count": "desc"
	        },
	        "size": 50
	      },
	      "aggs": {
	        "3": {
	          "terms": {
	            "field": "host.hostname",
	            "order": {
	              "_count": "desc"
	            },
	            "size": 5
	          },
	          "aggs": {
	            "4": {
	              "terms": {
	                "field": "destination.ip",
	                "order": {
	                  "_count": "desc"
	                },
	                "size": 5
	              },
	              "aggs": {
	                "5": {
	                  "terms": {
	                    "field": "destination.port",
	                    "order": {
	                      "_count": "desc"
	                    },
	                    "size": 5
	                  },
	                  "aggs": {
	                    "6": {
	                      "terms": {
	                        "field": "source.ip",
	                        "order": {
	                          "_count": "desc"
	                        },
	                        "size": 5
	                      },
	                      "aggs": {
	                        "7": {
	                          "terms": {
	                            "field": "source.port",
	                            "order": {
	                              "_count": "desc"
	                            },
	                            "size": 5
	                          }
	                        }
	                      }
	                    }
	                  }
	                }
	              }
	            }
	          }
	        }
	      }
	    }
	  },
	  "size": 0,
	  "_source": {
	    "excludes": []
	  },
	  "stored_fields": [
	    "*"
	  ],
	  "script_fields": {},
	  "docvalue_fields": [
	    {
	      "field": "@timestamp",
	      "format": "date_time"
	    },
	    {
	      "field": "event.created",
	      "format": "date_time"
	    },
	    {
	      "field": "event.end",
	      "format": "date_time"
	    },
	    {
	      "field": "event.start",
	      "format": "date_time"
	    },
	    {
	      "field": "file.accessed",
	      "format": "date_time"
	    },
	    {
	      "field": "file.created",
	      "format": "date_time"
	    },
	    {
	      "field": "file.ctime",
	      "format": "date_time"
	    },
	    {
	      "field": "file.mtime",
	      "format": "date_time"
	    },
	    {
	      "field": "process.start",
	      "format": "date_time"
	    },
	    {
	      "field": "system.audit.host.boottime",
	      "format": "date_time"
	    },
	    {
	      "field": "system.audit.package.installtime",
	      "format": "date_time"
	    },
	    {
	      "field": "system.audit.user.password.last_changed",
	      "format": "date_time"
	    }
	  ],
	  "query": {
	    "bool": {
	      "must": [],
	      "filter": [
	        {
	          "match_all": {}
	        },
	        {
	          "bool": {
	            "should": [
	              {
	                "match": {
	                  "destination.port": 22
	                }
	              }
	            ],
	            "minimum_should_match": 1
	          }
	        },
	        {
	          "match_phrase": {
	            "event.dataset": {
	              "query": "socket"
	            }
	          }
	        },
	        {
	          "range": {
	            "@timestamp": {
	              "format": "strict_date_optional_time",
	              "gte": post_time.utcfromtimestamp(time.time()-10).strftime('%Y-%m-%dT%H:%M:%SZ'),
	              "lte": post_time.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')
	            }
	          }
	        }
	      ],
	      "should": [],
	      "must_not": [
	        {
	          "match_phrase": {
	            "source.ip": {
	              "query": "127.0.0.1"
	            }
	          }
	        },
	        {
	          "match_phrase": {
	            "destination.ip": {
	              "query": "127.0.0.1"
	            }
	          }
	        }
	      ]
	    }
	  }
	}
	return data

def intrusion_check(info):
	data_json = json.loads(info)

	all_hits = data_json['hits']['total']['value']
	if all_hits >= 20:
		data = data_json['aggregations']['2']['buckets']
		date = datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')
		print(f'[{date}] 检测到攻击流量！')
		intrusion_alert(data)

	elif all_hits == 0:
		date = datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')
		print(f'[{date}] 好得很')
	else:
		date = datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')
		print(f'[{date}] 好得很')

def intrusion_alert(data):
	for i in data:
		timestamp = i['key_as_string']
		hostname = i["3"]["buckets"][0]['key']
		destinationip = i['3']['buckets'][0]['4']['buckets'][0]['key']
		destinationport = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['key']
		sourceip = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['6']['buckets'][0]['key']
		sourceport = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['6']['buckets'][0]['7']['buckets'][0]['key']
		print(f"{timestamp} {hostname} {destinationip}:{destinationport} <=== {sourceip}:{sourceport}")
		destinationport = str(destinationport)
		if destinationip in flagip:
			flagip[destinationip] = flagip[destinationip] +1
		else: flagip[destinationip] = 1

		if destinationport in flagport:
			flagport[destinationport] = flagport[destinationport] +1
		else: flagport[destinationport] = 1

		if sourceip in flagsourceip:
			flagsourceip[sourceip] = flagsourceip[sourceip] +1
		else: flagsourceip[sourceip] = 1

		if hostname in flaghostname:
			flaghostname[hostname] = flaghostname[hostname] +1
		else: flaghostname[hostname] = 1
	# print(flagip)
	# print(flagport)
	# print(flagsourceip)
	realsourceip = max(flagsourceip.items(), key=operator.itemgetter(1))[0]
	realdestinationip = max(flagip.items(), key=operator.itemgetter(1))[0]
	realsourceport = max(flagport.items(), key=operator.itemgetter(1))[0]
	realhostname = max(flaghostname.items(), key=operator.itemgetter(1))[0]
	message = "IP: " + realdestinationip + " 的 " + realsourceport + " 端口收到攻击,攻击IP为 " + realsourceip
	SendSMS(timestamp,realhostname,message)



def checkfile(url):

	post_time = datetime.datetime
	print(f"[{post_time.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')}] 发送请求...")
	data = make_post_dict(post_time)
	r = requests.post(url, json=data).text
	#print(r)
	intrusion_check(r)

	time.sleep(10)


if __name__ == "__main__":

	url = 'http://your_ip_address:9200/auditbeat-*/_search?'
	main()

	