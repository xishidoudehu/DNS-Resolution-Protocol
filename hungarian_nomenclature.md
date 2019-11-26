# Hungarian Nomenclature

Attribute + Type + Description，E.g

```c
int iNumber;		// i express int.
char *pPrintInfo;	// c express char.
```

## Attribute

- g_      global variable
- m_    class member variable
- s_      static variable
- c_      constant variable

## Type

| Prefix | Type                                          |
| ------ | --------------------------------------------- |
| a      | Array                                         |
| b      | Boolean                                       |
| by     | Byte                                          |
| c      | Char                                          |
| cb     | Char Byte                                     |
| cr     | ColorRef                                      |
| d      | Double                                        |
| f      | Float                                         |
| cx, cy | Count of x or y                               |
| w      | Word, unsigned int                            |
| dw     | Double Word, unsigned long int                |
| h      | Handle                                        |
| i      | Int                                           |
| n      | short int                                     |
| l      | Long Int                                      |
| np     | Near Pointer                                  |
| p      | Pointer                                       |
| s      | String                                        |
| sz     | String with zero end                          |
| lp     | Long Pointer                                  |
| lpsz   | LPSTR  32-bit string pointer                  |
| lpsz   | LPCSTR  32-bit constant string pointer        |
| lpsz   | LPCTSTR  32-bit UNICODE type constant pointer |

## Others

- class 	  CFtpServer
- struct        SUserNode
- function   SetUserMaxClient
- filename  aes_ecb.cpp 