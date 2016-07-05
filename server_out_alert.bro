# This script detect and log server connect out to others


module ServerOutAlert;

const ServerSubnets: set[subnet] = {192.168.0.0/16, 10.0.0.0/8} &redef;

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

event new_connection(c: connection)
{
    if ( ! c?$id )
        return;
    if ( ! c$id?$orig_h )
        return;

    for (serversubnet in ServerSubnets)
    {   

      if ( c$id$orig_h in serversubnet )
        NOTICE([$note=Server_Out_Alert,
                $msg=fmt("Local Server IP %s Of Subnet %s connection to Outside IP %s ", cat(c$id$orig_h), serversubnet, cat(c$id$resp_h)),
                $uid=c$uid,
                $id=c$id,
                $identifier=cat(c$uid)]);
    }   

}


event connection_state_remove(c: connection) &priority=-10
{
    if ( ! c?$id )
        return;
    if ( ! c$id?$orig_h )
        return;

    for (serversubnet in ServerSubnets)
    {   

      if ( c$id$orig_h in serversubnet )
      {
       local rec: ServerOutAlert::Info = [
                        $ts=network_time(),
                        $uid=c$uid,
                        $id=c$id,
                        $proto=c$conn$proto,
                        $service=c$conn$service,
                        $duration=c$conn$duration,
                        $orig_ip_bytes=c$conn$orig_ip_bytes,
                        $conn_state=c$conn$conn_state
                    ];

        Log::write(ServerOutAlert::LOG, rec);
	}

    }   

}
