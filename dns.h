#ifndef dns_h
#define dns_h
#include <stdio.h>
#include <WinSock2.h>
#include <time.h>

/************************************************************************/
/*						   	STRUCT: DNSHeader                           */
/************************************************************************/
/* The Structure which will be allocated for each User 
 Transaction ID (two bytes):
	-usTransID-------Constant identification data specified by the client.
 Flags (two bytes):
	-RD (1 bit)--------------Indicates expected recursion.
	-TC (1 bit)--------------Indicates that it can be truncated.
	-AA (1 bit)--------------Indicates authorized answer.
	-opcode (4bit)-----------0 means standard query, 1 means reverse query, 2 means server status request.
	-QR (1 bit)--------------Query/response flag,0 is the query,1 is the response.
	-rcode (4 bit)-----------Indicates the return code.
	-zero (3 bit)------------Must be 0.
	-RA (1 bit)--------------Indicates that recursion is available.
 Variable (eight bytes):
	-Questions-----------Request the body of the data,This is the only one in the request package. 
	-AnswerRRs-----------The body of the response data.
	-AuthorityRRs--------Domain name management agency.
	-AdditionalRRs-------Additional information data.
*/
#pragma pack(push, 1)
struct DNSHeader
{
    unsigned short usTransID;
	
    unsigned char RD : 1;            
    unsigned char TC : 1;            
    unsigned char AA : 1;           
    unsigned char opcode : 4;       
    unsigned char QR : 1;            
	
    unsigned char rcode : 4;        
    unsigned char zero : 3;         
    unsigned char RA : 1;    
	
    unsigned short Questions;        
    unsigned short AnswerRRs;        
    unsigned short AuthorityRRs;     
    unsigned short AdditionalRRs;    
};
#pragma pack(pop)


/************************************************************************/
/*						   THE CLASS: dns                               */
/************************************************************************/
class dns
{
	/*****************************/
	/*         PUBLIC			 */                             
	/*****************************/
	public:
		/*****************************/
		/*         USER			     */                             
		/*****************************/

		/* Initialize socket and dns resolving parameters. 
		 Aguments:
			-IN nNetTimeout------------Set the socket's timeout for sending and receving data pack.
			-IN szDomainName-----------Set the private that a domain name to be resolved.
			-IN szDnsServer------------
		 Returns:
			-PRIVATE mySocket----------Get a socket for sending and receiving date pack.
			-PRIVATE myUsId------------Get a session id for sending and receiving date pack.
			-PRIVATE myDomainName-----------The domain name which need to be resolved.
			-PRIVATE myDnsServer--------------Domain name resolution server. 
		*/
		void InitialDnsPack(IN int nNetTimeout,
							IN char *szDomainName, 
							IN const char *szDnsServer);
		/* Query message assembly and sending.
		 Aguments:
			-PRIVATE myDomainName-----------The domain name which need to be resolved.
			-PRIVATE DnsServer--------------Domain name resolution server. 
			-PRIVATE myUsID-----------------Session ID of sending and receiving dns data pack.
			-PRIVATE mySocket---------------A socket need to sending pack.
		 Returns:
			-Flase---------Sending packet failed.
			-True----------Sending packet success. 
		*/
		bool SendDnsPack();
		/* Receive response message,get IP address or connection failed. 
		 Aguments:
			-PRIVATE myUsID------------Session ID of sending and receiving dns data pack.
			-PRIVATE mySocket----------A socket need to receiving pack.
		 Returns:
			-printf parsed ip.
		*/
		void RecvDnsPack();
		/* Close the socket.
		 Aguments:
			-PRIVATE mySocket---------A pointer to close the udp communication process.
		 Returns:
		*/
		void CloseSocket();

	
	/*****************************/
	/*         PRIVATE			 */                             
	/*****************************/
	private:
		/* Initial the following arguments in [InitialDnsPack].
 		Arguments:
			-mySocket----------Socket for sending and receiving packets.
			-myUsId------------Randomly generated session id for [SenDnsPack] and [RecvDNsPack].
			-myDomainName------A domain name that need to resolving for [SendDnsPack].
			-myDnsServer-------A dns server that could resolving domain name for [SendDnsPack].
		*/
		SOCKET mySocket;
		unsigned short myUsId;
		char *myDomainName;
		const char *myDnsServer;
			
};	

#endif



