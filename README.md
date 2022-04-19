# windows-command-output-logstash-filter

### Here is some simple Grok+Regex to parsing Windows Command Output
If you can't install the agent on the host and you just can take the system output command. Here are some logstash filters to help you parse some windows command output.

##Ipconfig output:
```
Sample : 
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.0.0.123
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
 ```
 
```
filter
{
  grok {
    match => { "message" => "(\s+)(%{DATA:ipconfig_component}\ . .+)(\s+):(\s+)%{GREEDYDATA:Value}"}
  }
}
```

## Microsoft Windows Firewall
```
Sample:
1990-02-10 11:22:33 ALLOW UDP 10.0.0.123 10.0.0.255 137 137 0 - - - - - - - SEND
 ```

```
filter
{ 
  grok {
     match => { "message" => "%{TIMESTAMP_ISO8601:TimeStamp} %{WORD:Action} %{WORD:Protocol} %{IPV4:src} %{IPV4:dst} (%{INT:SrcPort}|-) (%{INT:DStPort}|-) %{INT:Size} %{GREEDYDATA:Flags} %{GREEDYDATA:Direction}"}
  }
  date {
        match => ["TimeStamp", "yyyy-MM-dd HH:mm:ss","ISO8601"]
  }
 }
 ```
## Active Connections / Netstat:
```
Sample:
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       3324
```

```
filter
{
  grok {
     match => { "message" => "(\s+)%{WORD:Proto}(\s+)(%{IPV6}|%{IPV4:Local_Address}|.*):(%{INT:LocalAddress_Port}|-)(\s+)(%{IPV6}|%{IPV4:Foreign_Address}|.*):(%{INT:Foreign_Port}|.*)(\s+)(%{WORD:State}|)(\s+)%{WORD:PID}"}
  }
}
```

## AV_Status
```
Sample:
AMRunningMode                    : Normal
AMServiceEnabled                 : True
AMServiceVersion                 : 2.11.223.1
AntispywareEnabled               : True
AntispywareSignatureAge          : 0

```

```
filter
{
  grok {
    match => { "message" => "%{WORD:AV_Component}(\s+):(\s+)%{GREEDYDATA:Value}"}
  }
}
```


## Additional configuration
If there are some error unicode string when you parse .txt file. You can delete the unicode use this syntax:

In my case, the unicode is `{:text=>"\\xFF\\xFE\\r\\u0000", :expected_charset=>"UTF-8"}`

```
filter {
        ruby { code => 'event.set("message", event.get("message").gsub("\u0000", "".encode("utf-8")))' }
        ruby { code => 'event.set("message", event.get("message").gsub("\r", "".encode("utf-8")))' }
        ruby { code => 'event.set("message", event.get("message").gsub("\xFF", "".encode("utf-8")))' }
        ruby { code => 'event.set("message", event.get("message").gsub("\xFE", "".encode("utf-8")))' }
        .....
        }
```
