# windows-command-output-logstash-filter

### Here is some simple Grok+Regex to parsing Windows Command Output
If you can't install the agent on the host and you just can take the system output command. Here are some logstash filters to help you parse some windows command output.

Ipconfig output:
```
filter
{
  grok {
    match => { "message" => "(\s+)(%{DATA:ipconfig_component}\ . .+)(\s+):(\s+)%{GREEDYDATA:Value}"}
  }
}
```

Microsoft Windows Firewall
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
Active Connections / Netstat:
```
filter
{
  grok {
     match => { "message" => "(\s+)%{WORD:Proto}(\s+)(%{IPV6}|%{IPV4:Local_Address}|.*):(%{INT:LocalAddress_Port}|-)(\s+)(%{IPV6}|%{IPV4:Foreign_Address}|.*):(%{INT:Foreign_Port}|.*)(\s+)(%{WORD:State}|)(\s+)%{WORD:PID}"}
  }
}
```

AV_Status
```
filter
{
  grok {
    match => { "message" => "%{WORD:AV_Component}(\s+):(\s+)%{GREEDYDATA:Value}"}
  }
}
```
