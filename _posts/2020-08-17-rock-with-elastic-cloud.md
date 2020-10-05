---
layout: default
title: "8/17/2020 - RockNSM and Elastic Cloud"
tags: feed
---
# 8/02/2020 - RockNSM and Elastic Cloud
- [Packets](http://malware-traffic-analysis.net/2020/03/11/index.html)
- [Getting Data into ROCK](https://github.com/huntops-blue/huntops-blue.github.io/blob/master/rock-install.md#getting-data-into-rock)

Running a ROCK sensor locally can make a lot of sense, and in most cases, that's an absolutely fine use-case. That said, you may be running ROCK (at home or in an office) and you want to be able to access your sensor data from anywhere. While you can use a VPN setup or expose services directly to the Internet, there is another approach using Elastic's SaaS offering, [Elastic Cloud](https://cloud.elastic.co). Yes, before I forget, Elastic Cloud is approved for government use and certified with [FedRAMP](https://marketplace.fedramp.gov/#!/product/elastic-cloud?sort=productName&productNameSearch=elastic).

Additional benefits are that you don't have to roll your own security implementation, everything in Elastic Cloud uses TLS and can be configured with OAuth, and you get access to all of the Platinum Elastic features, like Machine Learning.

As a downside, you do have to pay for Elastic Cloud and the Docket workflow is a bit different.

In this scenario, we'll be using both Elasticsearch and Kibana as SaaS.

Sending sensor data to Elastic Cloud is pretty simple, either as an update to an existing build or as a fresh one.

**Prepatory Work**

First, you'll need an [Elastic Cloud](https://cloud.elastic.co) account. I think you get 2-weeks free?

![](/images/8-17-20-1.png)

![](/images/8-17-20-2.png)

From here, let's create a deployment.

![](/images/8-17-20-3.png)

You can select all of the defaults. If you need to adjust the specs, you can do that at any time, but for now, we'll just click through the creation wizard.

![](/images/8-17-20-4.png)

That'll take a few minutes to create your deployment; but once it's done, you'll get your Cloud ID (which is used for all the configurations moving forward) and your credentials to log into Kibana.

![](/images/8-17-20-5.png)

That's it from a prep perspective.

**Existing Build**

If you already have a sensor, there are only 2 things that have to get done:

1. Turn off and disable Elasticsearch and Kibana
1. Make a small update to a Logstash configuration

Let's shut down and disable Elasticsearch and Kibana on our sensor.
```
sudo systemctl stop elasticsearch kibana
sudo systemctl disable elasticsearch kibana
```

Let's make a configuration change to `/etc/logstash/conf.d/logstash-9999-output-elasticsearch.conf` to point to your Elastic Cloud account.

In the configuration files, we'll be adding a few fields - `cloud_auth` and `cloud_id`. `cloud_auth` is the username and passphrase that was generated when you created your Elastic  Cloud deployment. The username is `elastic` and the passphrase was set automatically. The format is `username:passphrase`, so in our example, it will be `cloud_auth => "elastic:passphrase"`. The `cloud_id` field is the Cloud ID you were presented when you created your Elastic Cloud deployment and is formatted `cloud_id => "deployment_name:base64-encoded-string"`. If you followed my screenshots above, the `deployment_name` is `rocknsm`, so it would be `cloud_id => "rocknsm:base64-encoded-string"`.

Finally, comment out (or remove) the `hosts => ` line.

This needs to be updated throughout the Logstash configuration file. Example:
```
output {
  # Requires event module and category
  if [event][module] and [event][category] {

    # Requires event dataset
    if [event][dataset] {
      elasticsearch {
                    # hosts => ["127.0.0.1:9200"]
                    cloud_auth => "elastic:passphrase"
                    cloud_id => "rocknsm:base64-encoded-string"
                    index => "ecs-%{[event][module]}-%{[event][category]}-%{+YYYY.MM.dd}"
          manage_template => false
      }
    }

    else {
      # Suricata or Zeek JSON error possibly, ie: Suricata without a event.dataset seen with filebeat error, but doesn't have a tag
      if [event][module] == "suricata" or [event][module] == "zeek" {
        elasticsearch {
                    # hosts => ["127.0.0.1:9200"]
                    cloud_auth => "elastic:passphrase"
                    cloud_id => "rocknsm:base64-encoded-string"
                    index => "parse-failures-%{+YYYY.MM.dd}"
            manage_template => false
        }
      }
      else {
        elasticsearch {
                    # hosts => ["127.0.0.1:9200"]
                    cloud_auth => "elastic:passphrase"
                    cloud_id => "rocknsm:base64-encoded-string"
                    index => "ecs-%{[event][module]}-%{[event][category]}-%{+YYYY.MM.dd}"
            manage_template => false
        }
      }
    }
  }

  else if [@metadata][stage] == "fsfraw_kafka" {
    elasticsearch {
                    # hosts => ["127.0.0.1:9200"]
                    cloud_auth => "elastic:passphrase"
                    cloud_id => "rocknsm:base64-encoded-string"
                    index => "fsf-%{+YYYY.MM.dd}"
        manage_template => false
    }
  }

  else if [@metadata][stage] == "_parsefailure" {
    elasticsearch {
                    # hosts => ["127.0.0.1:9200"]
                    cloud_auth => "elastic:passphrase"
                    cloud_id => "rocknsm:base64-encoded-string"
                    index => "parse-failures-%{+YYYY.MM.dd}"
        manage_template => false
    }

  }

  # Catch all index that is not RockNSM or ECS or parse failures
  else {
    elasticsearch {
                    # hosts => ["127.0.0.1:9200"]
                    cloud_auth => "elastic:passphrase"
                    cloud_id => "rocknsm:base64-encoded-string"
                    index => "indexme-%{+YYYY.MM.dd}"
        manage_template => false
    }
  }
}
```
Save that configuration and then test Logstash w/`sudo -u logstash -g logstash /usr/share/logstash/bin/logstash "--path.settings" "/etc/logstash" -t` and, after a few minutes, you should see `Configuration OK`.

Let's restart Logstash and validate that everything is working as intended.

```
sudo systemctl restart logstash
```

Wait a minute and then run either `rockctl status` or `systemctl status logstash`. What you're looking for is that it's been running more than a minute. If there are issues, Logstash just restarts without a whole lot of indication that it's not healthy.

![](/images/8-17-20-6.png)

**Test Data**

Lets test the sample data listed at the top of the page and replay it to test everything.

=== 8/17 pause ===

Looks good, and happy hunting!

**Closing Thoughts**

If you're looking for new detection rules, check out [Elastic's public repository](https://www.elastic.co/blog/elastic-security-opens-public-detection-rules-repo). If you make a rule you like, please feel free to contribute it to the [project](https://github.com/elastic/detection-rules)!
