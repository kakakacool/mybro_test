# This script detect and log server connect out to others

@load base/utils/site
module ServerOutAlert;

const ServerSubnets: set[subnet] = {192.168.0.0/16, 10.0.0.0/8} &redef;
const whiteportlist: set[port] ={80/tcp,443/tcp,53/udp,5353/udp, 25/tcp};

redef Site::local_nets =  {192.168.0.0/16, 10.0.0.0/8};

redef enum Notice::Type += {
    Server_Out_Alert,
};

redef enum Log::ID += { LOG };

type Info: record {
        ts:                time        &log;
        uid:               string      &log;
        id:                conn_id     &log;
        proto:             transport_proto &log &optional;
        service:           string      &log &optional;
        duration:          interval        &log &optional;
        orig_ip_bytes: count      &log &optional;
        conn_state:   string          &log &optional;
    };


global log_outconn: event(rec: Info);

event bro_init() &priority=5
{
    Log::create_stream(ServerOutAlert::LOG, [$columns=Info, $ev=log_outconn]);
}

event connection_state_remove(c: connection)
{
    if ( ! c?$id )
        return;
    if ( ! c$id?$orig_h )
        return;

    for (serversubnet in ServerSubnets)
    {   

      if ( c$id$orig_h in serversubnet )
      {
        
        local isdstinlocal = F;
        
        for (internaldstsubnet in ServerSubnets)
        {
            if (c$id$resp_h in internaldstsubnet) 
              {
								isdstinlocal =T;
            }
        }
        
        if (!isdstinlocal)
        	{
                  if (c?$conn)
                      {
                      	
                      if(c$id$resp_p !in whiteportlist)
		                  		NOTICE([$note=Server_Out_Alert,
		                      $msg=fmt("Local Server IP %s Of Subnet %s connection to Outside IP %s ", cat(c$id$orig_h), serversubnet, cat(c$id$resp_h)),
		                      $uid=c$uid,
		                      $id=c$id,
		                      $identifier=cat(c$uid)]);
                      
                        
                       local rec: ServerOutAlert::Info = [
                              $ts=network_time(),
                              $uid=c$uid,
                              $id=c$id,
                              $proto=c$conn$proto
                          ];
                      
                      if(c$conn?$service)
                        rec$service=c$conn$service; 
                        
                      if(c$conn?$duration)
                        rec$duration=c$conn$duration;
                        
                      if(c$conn?$orig_ip_bytes)
                        rec$orig_ip_bytes=c$conn$orig_ip_bytes;
                      
                      if(c$conn?$conn_state)
                        rec$conn_state=c$conn$conn_state;
                        

                      Log::write(ServerOutAlert::LOG, rec);
                    }
        	}
      }

    }   
}
