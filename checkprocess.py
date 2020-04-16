 #!/usr/bin/env python3

import requests
import os
import time
import datetime
import re
import json
from sendsms import SendSMS
hostnamemulitple = actionmultiple = processnamemultiple = argmultiple = ""

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
                  "field": "process.executable",
                  "order": {
                    "_count": "desc"
                  },
                  "size": 5
                },
                "aggs": {
                  "5": {
                    "terms": {
                      "field": "process.args",
                      "order": {
                        "_count": "desc"
                      },
                      "size": 5
                    },
                    "aggs": {
                      "6": {
                        "terms": {
                          "field": "event.action",
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
                "query": "process"
              }
            }
          },
          {
            "range": {
              "@timestamp": {
                "format": "strict_date_optional_time",
                "gte": post_time.utcfromtimestamp(time.time()-12).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "lte": post_time.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')
              }
            }
          }
        ],
        "should": [],
        "must_not": [
          {
            "bool": {
              "should": [
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/dbus-daemon"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/python"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/python2.7"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/sshd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/nginx"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/dovecot/stats"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/share/metricbeat/bin/metricbeat"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/php-fpm"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/v2ray/v2ray"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/haproxy"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/mysqld"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/local/php/sbin/php-fpm"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/memcached"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/bash"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/sleep"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/vmtoolsd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/VGAuthService"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/tee"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/perl"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/gawk"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/freshclam"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/init"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/auditd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/udevd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/rpcbind"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/lib/systemd/systemd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/lvmetad"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/auditd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/chronyd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/rsyslogd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/crond"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/NetworkManager"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/dhclient"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/lib/systemd/systemd-journald"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/lib/systemd/systemd-udevd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/agetty"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/lib/polkit-1/polkitd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/lib/systemd/systemd-logind"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/irqbalance"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/postfix/master"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/postfix/qmgr"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/root/chinadns-1.3.2/src/chinadns"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/share/auditbeat/bin/auditbeat"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/postfix/pickup"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/local/mysql/bin/mysqld"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/local/nginx/sbin/nginx"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/wpa_supplicant"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/hald-addon-input"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/hald-addon-acpi "
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/share/metricbeat/bin/metricbeat-god"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/mingetty"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/rsyslogd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/bin/dbus-daemon"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/modem-manager"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/rpc.statd"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/sbin/dhclient"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/hald"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/hald-runner"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/hald-addon-acpi"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/share/auditbeat/bin/auditbeat-god"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/bin/sleep"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/share/filebeat/bin/filebeat"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/nm-dispatcher.action"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/nm-dispatcher"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/sbin/anacron"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/lib/systemd/systemd-hostnamed"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/libexec/nm-dhcp-helper"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/bin/gawk"
                  }
                },
                {
                  "match_phrase": {
                    "process.executable": "/usr/bin/mandb"
                  }
                }
              ],
              "minimum_should_match": 1
            }
          },
          {
            "bool": {
              "should": [
                {
                  "match_phrase": {
                    "host.hostname": "mail.jinzz.cc"
                  }
                }
              ],
              "minimum_should_match": 1
            }
          },
          {
            "match_phrase": {
              "process.args": {
                "query": "/bin/bash"
              }
            }
          },
          {
            "match_phrase": {
              "process.args": {
                "query": "/usr/sbin/ksmtuned"
              }
            }
          },
          {
            "match_phrase": {
              "process.args": {
                "query": "-bash"
              }
            }
          },
          {
            "match_phrase": {
              "process.executable": {
                "query": ""
              }
            }
          },
          {
            "match_phrase": {
              "process.executable": {
                "query": "/usr/bin/vim"
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
    action = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['6']['buckets'][0]['key']
    processname = i['3']['buckets'][0]['4']['buckets'][0]['key']
    arg = i['3']['buckets'][0]['4']['buckets'][0]['5']['buckets'][0]['key']
    if len(data) > 1:
      #print("12345")
      #print(f"{timestamp}{hostname}{filename}{action}{hash}")
      global hostnamemulitple
      global actionmultiple
      global processnamemultiple
      global argmultiple
      hostnamemulitple += " " + hostname
      actionmultiple += " " + action
      processnamemultiple += " " + processname
      argmultiple += " " + arg
      #print(hostname)
      #print(hostnamemulitple)
      
    else:
      #print("11111")
      #print(f"{timestamp}{hostname}{filename}{action}{hash}")
      message = "*发现异常进程* " + processname + " 操作为" + action + " 进程参数为" + arg
      print(message)
      SendSMS(timestamp,hostnamemulitple,message)
  if len(data) > 1:
    #hostnamemulitplestr = hostnamemulitplestr = actionmultiplestr = filenamemultiplestr = ""
    #hostnamemulitplestr = " ".join(hostnamemulitple)
    #actionmultiplestr = " ".join(actionmultiple)
    #filenamemultiplestr = " ".join(filenamemultiple)
    message = "*发现多个异常进程*" + processnamemultiple + " 操作为" + actionmultiple + " 进程参数为" + argmultiple
    print(message)
    SendSMS(timestamp,hostnamemulitple,message)
    hostnamemulitple = actionmultiple = filenamemultiple = argmultiple = ""

def checkfile(url):

  post_time = datetime.datetime
  # print(post_time.utcfromtimestamp(time.time()))
  print(f"[{post_time.utcfromtimestamp(time.time()).strftime('%Y-%m-%dT%H:%M:%SZ')}] 发送请求...")
  data = make_post_dict(post_time)
  r = requests.post(url, json=data).text
  #r = '{"took":29,"timed_out":false,"_shards":{"total":5,"successful":5,"skipped":0,"failed":0},"hits":{"total":{"value":3,"relation":"eq"},"max_score":null,"hits":[]},"aggregations":{"2":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":1586889144210,"key_as_string":"2020-04-14T18:32:24.210Z","doc_count":1,"3":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"dev.jinzz.cc","doc_count":1,"4":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"/etc/passwd","doc_count":1,"5":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"moved","doc_count":1,"6":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"c9fa0d5654adfc84721535fff4d6074e321d2ed2","doc_count":1}]}}]}}]}}]}},{"key":1586889144211,"key_as_string":"2020-04-14T18:32:24.211Z","doc_count":1,"3":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"dev.jinzz.cc","doc_count":1,"4":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"/etc/passwd~","doc_count":1,"5":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"created","doc_count":1,"6":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"86dbf118f498cad1ff929aa57c64dafb9d345fb8","doc_count":1}]}}]}}]}}]}},{"key":1586889144212,"key_as_string":"2020-04-14T18:32:24.212Z","doc_count":1,"3":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"dev.jinzz.cc","doc_count":1,"4":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"/etc/passwd","doc_count":1,"5":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"created","doc_count":1,"6":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,"buckets":[{"key":"c9fa0d5654adfc84721535fff4d6074e321d2ed2","doc_count":1}]}}]}}]}}]}}]}}}'
  #print(r)
  intrusion_check(r)

  time.sleep(10)

if __name__ == "__main__":

  url = 'http://your_ip_address:9200/auditbeat-*/_search?'
  main()

  
