# DNS Strolch

DNS proxy that blocks all request by default 
and only allows previously specified entries through to an DOH (DNS over HTTPS) request.

run example:

    cargo run 
    #defaults to:
    cargo run 0.0.0.0:53
  
Set the dns server of your connection to 0.0.0.0.

The file dns_list.txt is used to store the allowed and blocked domains:

dns_list.txt format example:
    
    # allowed domains that the strolch will try to resolve
    www.example.org
    github.com
    
    # lines starting with ! are ignored domains
    !vortex.data.microsoft.com
    
    # * can be used to match all subdomains
    !*.data.microsoft.com
    *.github.io


The file hardcoded.txt stores hardcoded ip responses.

hardcoded.txt format example:

    test.test               127.0.0.1
    ipv6::test.test         ::1

On Windows Toast notifications show unkown request and give the option to block or allow them.

