 #!/usr/bin/env python3

import requests
import os
import time
import datetime
import re
import json
from sendsms import SendSMS
hostnamemulitple = actionmultiple = filenamemultiple = ""

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
	            "size": 50
	          },
	          "aggs": {
	            "4": {
	              "terms": {
	                "field": "file.path",
	                "order": {
	                  "_count": "desc"
	                },
	                "size": 50
	              },
	              "aggs": {
	                "5": {
	                  "terms": {
	                    "field": "event.action",
	                    "order": {
	                      "_count": "desc"
	                    },
	                    "size": 5
	                  },
	                  "aggs": {
	                    "6": {
	                      "terms": {
	                        "field": "hash.sha1",
	                        "order": {
	                          "_count": "desc"
	                        },
	                        "size": 50
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
	          "match_all": {}
	        },
	        {
	          "match_phrase": {
	            "event.dataset": {
	              "query": "file"
	            }
	          }
	        },
	        {
	          "exists": {
	            "field": "hash.sha1"
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
	          "regexp": {
	            "file.path": {
	              "value": ".*swp.*",
	              "flags": "ALL",
	              "max_determinized_states": 10000,
	              "rewrite": "constant_score"
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
	if all_hits != 0:
		data = data_json['aggregations']['2']['buckets']
		intrusion_alert(data)

	elif all_hits == 0:
		date = datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')
		print(f'[{date}] 好得很')

def intrusion_alert(data):
	for i in data:
		timestamp = i['key_as_string']
		hostname = i["3"]["buckets"][0]['key']
		action = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['key']
		filename = i['3']['buckets'][0]['4']['buckets'][0]['key']
		hash = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['6']['buckets'][0]['key']
		if len(data) > 1:
			global hostnamemulitple
			global actionmultiple
			global filenamemultiple
			hostnamemulitple += " " + hostname
			actionmultiple += " " + action
			filenamemultiple += " " + filename
			
		else:
			message = "*文件发生异常变动*" + filename + " 操作为" + action + " 变动后的文件hash为" + hash
			print(message)
			SendSMS(timestamp,hostnamemulitple,message)
	if len(data) > 1:
		message = "*多个文件发生异常变动*" + filenamemultiple + " 操作为" + actionmultiple
		print(message)
		SendSMS(timestamp,hostnamemulitple,message)
		hostnamemulitple = actionmultiple = filenamemultiple = ""

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

	