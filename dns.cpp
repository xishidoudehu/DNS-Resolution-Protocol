#include "dns.h"


void dns::InitialDnsPack(IN int nNetTimeout, 
						 IN char *szDomainName, 
						 IN const char *szDnsServer)
{
	// Initial socket.
	WSADATA wsaData = {0};  
    if ( 0 != ::WSAStartup(MAKEWORD(2, 2), &wsaData) )
    {
        printf("WSAStartup fail \n");
        // return -1;
    } 
    this -> mySocket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (INVALID_SOCKET == this -> mySocket)
    {
        printf("socket fail \n");
        // return -1;
    }
	
	::setsockopt(this -> mySocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&nNetTimeout, sizeof(int));	// Set the sending time limit.
	::setsockopt(this -> mySocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&nNetTimeout,sizeof(int));	// Set the receiving time limit.

	//Initial session id, domain name, dns resolving server.
	srand((unsigned int)time(NULL));
	unsigned short usId = (unsigned short)rand();
	this -> myUsId = usId;
	this -> myDomainName = szDomainName;
	this -> myDnsServer = szDnsServer;
}


bool dns::SendDnsPack()
{
	SOCKET sendSocket = this -> mySocket;
	unsigned short usID = this -> myUsId;
	char *szDomainName = myDomainName;
	const char *szDnsServer = myDnsServer;

    bool bRet = false;
	int nRet = -1;
	unsigned short *usQueryType = NULL;
	BYTE* PText = NULL;

    if (sendSocket == INVALID_SOCKET 
        || szDomainName == NULL 
        || szDnsServer == NULL 
        || strlen(szDomainName) == 0 
        || strlen(szDnsServer) == 0)
    {
        return bRet;
    }
    
    unsigned int uiDnLen = strlen(szDomainName);

    // To determine the legality of a domain name, the first letter of a domain name cannot be a dot, 
	// The last name of a domain name cannot have two consecutive dot numbers. 
    if ('.' == szDomainName[0] || ( '.' == szDomainName[uiDnLen - 1] 
          && '.' == szDomainName[uiDnLen - 2]) 
       )
    {
        return bRet;
    }
    
    /* Convert a domain name to a format that matches the query message */
    // Example of the format of the query message:
    // jocent.me---------to----------6 j o c e n t 2 m e 0
    unsigned int uiQueryNameLen = 0;
    BYTE *pbQueryDomainName = (BYTE *)malloc(uiDnLen + 1 + 1);
    if (pbQueryDomainName == NULL)
    {
        return bRet;
    }
    // The length of the converted query field = Domain name length + 2
    memset(pbQueryDomainName, 0, uiDnLen + 1 + 1);

    /* The following loops function: */
    // If the domain name is jocent.me , it is converted to 6 j o c e n t , and some parts are not copied.
    // If the domain name is jocent.me., it is converted to 6 j o c e n t 2 m e.
    unsigned int uiPos    = 0;
    unsigned int i        = 0;
    for ( i = 0; i < uiDnLen; ++i)
    {
      if (szDomainName[i] == '.')
      {
          pbQueryDomainName[uiPos] = i - uiPos;
          if (pbQueryDomainName[uiPos] > 0)
          {
              memcpy(pbQueryDomainName + uiPos + 1, szDomainName + uiPos, i - uiPos);
          }
          uiPos = i + 1;
      }
    }
        
    // If the last name of the domain name is not a dot, then the above loop only converts part of it.
    // The following code continues to convert the rest, such as 2 m e.
    if (szDomainName[i-1] != '.')
    {
      pbQueryDomainName[uiPos] = i - uiPos;
      memcpy(pbQueryDomainName + uiPos + 1, szDomainName + uiPos, i - uiPos);
      uiQueryNameLen = uiDnLen + 1 + 1;
    }
    else
    {
      uiQueryNameLen = uiDnLen + 1;    
    }
    // Padding content  header + name + type + class
    DNSHeader *PDNSPackage = (DNSHeader*)malloc(sizeof(DNSHeader) + uiQueryNameLen + 4);
    if (PDNSPackage == NULL)
    {
        goto exit;
    }
    memset(PDNSPackage, 0, sizeof(DNSHeader) + uiQueryNameLen + 4);

    // Padding the header content.
    PDNSPackage->usTransID = htons(usID);  // ID
    PDNSPackage->RD = 0x1;   // Representing expectation recursion.
    PDNSPackage->Questions = htons(0x1);  // Convert to network byte order.

    // Padding the body content  name + type + class
    PText = (BYTE*)PDNSPackage + sizeof(DNSHeader);
    memcpy(PText, pbQueryDomainName, uiQueryNameLen);

    usQueryType = (unsigned short *)(PText + uiQueryNameLen);
    *usQueryType = htons(0x1);        // TYPE: A

    ++usQueryType;
    *usQueryType = htons(0x1);        // CLASS: IN    

    // The address of the DNS resolving server. 
    sockaddr_in dnsServAddr;
    dnsServAddr.sin_family = AF_INET;
    dnsServAddr.sin_port = ::htons(53);  // The port number of the DNS server is 53.
    dnsServAddr.sin_addr.S_un.S_addr = ::inet_addr(szDnsServer);
    
    // Send the query message.
	nRet = ::sendto(sendSocket,
        (char*)PDNSPackage,
        sizeof(DNSHeader) + uiQueryNameLen + 4,
        0,
        (sockaddr*)&dnsServAddr,
        sizeof(dnsServAddr));
    if (SOCKET_ERROR == nRet)
    {
        printf("DNSPackage Send Fail! \n");
        goto exit;
    }
    
    // printf("DNSPackage Send Success! \n");
    bRet = true;
    
// Unified resource clearing office.      
exit:
    if (PDNSPackage)
    {
        free(PDNSPackage);
        PDNSPackage = NULL;
    }

    if (pbQueryDomainName)
    {
        free(pbQueryDomainName);
        pbQueryDomainName = NULL;
    }
    
    return bRet;
}



void dns::RecvDnsPack()
{
	SOCKET recvSocket = this -> mySocket;
	unsigned short usId = this -> myUsId;

    if (recvSocket == INVALID_SOCKET)
    {
        return;
    }

    char szBuffer[256] = {0};        // Save received content.
    sockaddr_in servAddr = {0};
    int iFromLen = sizeof(sockaddr_in);

    int iRet = ::recvfrom(recvSocket,
        szBuffer,
        256,
        0,
        (sockaddr*)&servAddr,
        &iFromLen);
    if (SOCKET_ERROR == iRet || 0 == iRet)
    {
        printf("recv fail \n");
        return;
    }

    /* Resolving the received content */
    DNSHeader *PDNSPackageRecv = (DNSHeader *)szBuffer;
    unsigned int uiTotal       = iRet;        // Total number of bytes.
    unsigned int uiSurplus     = iRet;		  // The total number of bytes received.

    // Make sure the length of the received szBuffer is greater than sizeof (DNSHeader).
    if (uiTotal <= sizeof(DNSHeader))
    {
        printf("The length of the received content is illegal.\n");
        return;
    }

    // Confirm whether the ID in PDNSPackageRecv is consistent with that in the sent message.
    if (htons(usId) != PDNSPackageRecv->usTransID)
    {
        printf("The received packet ID does not match the query packet.\n");
        return;
    }

    // Confirm that Flags in PDNSPackageRecv is indeed a response message of DNS.
    if ( 0x01 != PDNSPackageRecv->QR )
    {
        printf("The received message is not a response message.\n");
        return;
    }

    // Get the type and class fields in Queries.
    unsigned char *pChQueries = (unsigned char *)PDNSPackageRecv + sizeof(DNSHeader);
    uiSurplus -= sizeof(DNSHeader);

    for ( ; *pChQueries && uiSurplus > 0; ++pChQueries, --uiSurplus ) { ; } // Skip the name field in Queries.

    ++pChQueries;
    --uiSurplus;

    if ( uiSurplus < 4 )
    {
        printf("The length of the received content is illegal.\n");
        return;
    }

    unsigned short usQueryType  = ntohs( *((unsigned short*)pChQueries) );
    pChQueries += 2;
    uiSurplus -= 2;

    unsigned short usQueryClass = ntohs( *((unsigned short*)pChQueries) );
    pChQueries += 2;
    uiSurplus -= 2;

    // Resolving the Answers field.
    unsigned char *pChAnswers = pChQueries;
    while (0 < uiSurplus && uiSurplus <= uiTotal)
    {
        // Skip the name field (useless).
        if ( *pChAnswers == 0xC0 )  // Stored pointer.
        {
            if (uiSurplus < 2)
            {
                printf("The length of the received content is illegal.\n");
                return;
            }
            pChAnswers += 2;       // Skip pointer field.
            uiSurplus -= 2;                
        }
        else        // Stored domain name.
        {
            // Skip the domain name because the ID has already been verified.
            for ( ; *pChAnswers && uiSurplus > 0; ++pChAnswers, --uiSurplus ) {;}    
            pChAnswers++;
            uiSurplus--;
        }

        if (uiSurplus < 4)
        {
            printf("The length of the received content is illegal.\n");
            return;
        }

        unsigned short usAnswerType = ntohs( *((unsigned short*)pChAnswers) );
        pChAnswers += 2;
        uiSurplus -= 2;

        unsigned short usAnswerClass = ntohs( *( (unsigned short*)pChAnswers ) );
        pChAnswers += 2;
        uiSurplus -= 2;

        if ( usAnswerType != usQueryType || usAnswerClass != usQueryClass )
        {    
            printf("The received content Type and Class are inconsistent with the sent message.\n");
            return;
        }

        pChAnswers += 4;    // Skip the Time to live field, this field is useless for the DNS Client.
        uiSurplus -= 4;

        if ( htons(0x04) != *(unsigned short*)pChAnswers )    
        {
            uiSurplus -= 2;     // Skip the data length field.
            uiSurplus -= ntohs( *(unsigned short*)pChAnswers ); // Skip the true length.

            pChAnswers += 2;
            pChAnswers += ntohs( *(unsigned short*)pChAnswers );    
        }
        else
        {
            if (uiSurplus < 6)
            {
                printf("The length of the received content is illegal.\n");
                return;
            }

            uiSurplus -= 6;
            // Type is A, Class is IN.
            if ( usAnswerType == 1 && usAnswerClass == 1)  
            {
                pChAnswers += 2;

                unsigned int uiIP = *(unsigned int*)pChAnswers;
                in_addr in = {0};
                in.S_un.S_addr = uiIP;
                printf("IP: %s\n", inet_ntoa(in));
    
                pChAnswers += 4;
            }
            else
            {
                pChAnswers += 6;
            }
        }
    }
}



void dns::CloseSocket()
{
	SOCKET cloSocket;
	cloSocket = this -> mySocket;
	closesocket(cloSocket);
	WSACleanup();
}





