# Monitor Implementation 

## Contents
- `types.go`: type declarations for monitor context and monitor context related methods
- `monitor-server.go`: monitor HTTP request routing
- `client-check-monitor.go`: Client-CheckMonitor functions
- `client-update-monitor.go`: Client-UpdateMonitor functions
- `monitor.go`: implementation of monitor functions

## types.go
-`Monitor_context`: monitor context is an object that contains all the configuration and storage information about the monitor
- `methods`: internal methods defined in this file includes savestorage, loadstorage, getobject, isduplicate, and storeobject 
## monitor.go
- `Queryloggers`: send HTTP get request to loggers
- `QueryAuthorities`: send HTTP get request to CAs
- `isLogger`: check if the entities is in the Loggers list from the public config file
- `IsAuthority`: check if the entities is in the CAs list from the public config file
- `Check_entity_pom`: check if there is a PoM aganist this entity 
- `AccuseEntity`: accuses the entity if its URL is provided   
- `Send_to_gossiper`: send the input gossip object to the gossiper  
- `PeriodicTasks` : query loggers/CAs once per MMD/MRD, accuse if the logger/CA is inactive
