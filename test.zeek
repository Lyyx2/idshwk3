global sourceIP:table[addr] of set[string]=table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
 {

if(name=="USER-AGENT")
{
   if(c$id$orig_h in sourceIP)
   {
     if(value !in sourceIP[c$id$orig_h])
     {
       add sourceIP[c$id$orig_h][value]; 
     }
   }
   else {
      sourceIP[c$id$orig_h]=set();
      add sourceIP[c$id$orig_h][value];
   }
}
}

event zeek_done()
{
	for(IP in sourceIP)
	{
	if(|sourceIP[IP]|>=3){
	print cat(IP)+" is a proxy";
	}
	}
}