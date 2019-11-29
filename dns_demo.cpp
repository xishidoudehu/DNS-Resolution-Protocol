#include "dns.h"

/************************************************************************/
/*			An example of calling DNS resolution function               */
/************************************************************************/

int main(int argc, char* argv[])
{
	int nNetTimeout = 3000;
	char *szDomainName = "Google.com";
	const char *szDnsServer = "8.8.8.8";
	dns demo;
	
	demo.InitialDnsPack(nNetTimeout, szDomainName, szDnsServer);						
	demo.SendDnsPack();
	demo.RecvDnsPack();								
	demo.CloseSocket();								

	return 0;
}
