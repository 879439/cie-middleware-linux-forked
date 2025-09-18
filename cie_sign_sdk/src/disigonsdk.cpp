// DigitSign.cpp : Defines the exported functions for the DLL application.
//

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <ctime>
#include <stdlib.h>
#include "disigonsdk.h"
#include "SignatureGenerator.h"
#include "ASN1/TimeStampData.h"
#include "ASN1/TimeStampResponse.h"
#include "CertStore.h"
#include "PdfVerifier.h"
#include "PdfSignatureGenerator.h"
#include "XAdESGenerator.h"
#include "M7MParser.h"
#include "XAdESVerifier.h"
#include "UUCLogger.h"
#include "UUCProperties.h"
#include "Base64.h"
#include "ASN1/ASN1Exception.h"
#include "RSA/sha2.h"
#include "IAS.h"
#include "CIESigner.h"
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include "podofo/podofo.h"
#include <string.h>

#ifdef WIN32
#include <shlwapi.h>
#endif

DECLARE_LOG;

#define DEFAULT_VERIFY_REVOCATION 0
#define DEFAULT_VERIFY_USER_CERT 0

typedef struct _DISIGON_SIGN_CONTEXT
{
    CBaseSigner*            pSigner;
    CSignatureGenerator*  pSignatureGenerator;
    char                    szInputFile[MAX_PATH];
    char                    szOutputFile[MAX_PATH];
    int                    nInputFileType;
    BOOL                    bDetached;
    BOOL                    bVerifyCert;
    char                    szPdfSubfilter[MAX_PATH];
    char                    szPdfReason[MAX_PATH];
    char                    szPdfName[MAX_PATH];
    char                    szPdfLocation[MAX_PATH];
    char                    szPdfReasonLabel[MAX_PATH];
    char                    szPdfNameLabel[MAX_PATH];
    char                    szPdfLocationLabel[MAX_PATH];
    int                    nPdfPage;
    float                fPdfLeft;
    float                fPdfBottom;
    float                fPdfWidth;
    float                fPdfHeight;
    char                    szPdfImagePath[MAX_PATH];
    char                    szPdfDescription[MAX_PATH];
    IAS*                pIAS;
    char                    szPIN[MAX_PATH];
    int                    nSlot;
    int                    nHashAlgo;
    char                    szAlias[MAX_PATH];
    char                    szTSAUrl[MAX_PATH];
    char                    szTSAUsername[MAX_PATH];
    char                    szTSAPassword[MAX_PATH];
    bool                    bCades;

} DISIGON_SIGN_CONTEXT;



typedef struct _DISIGON_VERIFY_CONTEXT
{
    char                    szInputFile[MAX_PATH];
    char                    szOutputFile[MAX_PATH];
    char                    szInputPlainTextFile[MAX_PATH]; // for detached
    int                    nInputFileType;
    BOOL                    bVerifyCRL;
} DISIGON_VERIFY_CONTEXT;

char g_szCACertDir[MAX_PATH];
bool g_bCACertDirSet = false;
char g_szVerifyProxy[MAX_PATH] = { 0 };
char* g_szVerifyProxyUsrPass = NULL;
int g_nVerifyProxyPort = -1;

UUCProperties g_mapOIDProps;

IAS* ias = NULL;
static const char kCIE_CA_BUNDLE_PEM[] = R"(-----BEGIN CERTIFICATE-----
MIIG4DCCBMigAwIBAgIIRmop7bWMajUwDQYJKoZIhvcNAQELBQAwgasxQjBABgNV
BAMMOU5hdGlvbmFsIHJvb3QgQ0EgZm9yIHRoZSBJdGFsaWFuIEVsZWN0cm9uaWMg
SWRlbnRpdHkgQ2FyZDE3MDUGA1UECwwuRGlyZXouIENlbnRyLiBwZXIgaSBTZXJ2
aXppIERlbW9ncmFmaWNpIC0gQ05TRDEfMB0GA1UECgwWTWluaXN0ZXJvIGRlbGwn
SW50ZXJubzELMAkGA1UEBhMCSVQwHhcNMTYwNjA2MTQzNzI0WhcNMzYwNjA2MTQz
NzI0WjCBqzFCMEAGA1UEAww5TmF0aW9uYWwgcm9vdCBDQSBmb3IgdGhlIEl0YWxp
YW4gRWxlY3Ryb25pYyBJZGVudGl0eSBDYXJkMTcwNQYDVQQLDC5EaXJlei4gQ2Vu
dHIuIHBlciBpIFNlcnZpemkgRGVtb2dyYWZpY2kgLSBDTlNEMR8wHQYDVQQKDBZN
aW5pc3Rlcm8gZGVsbCdJbnRlcm5vMQswCQYDVQQGEwJJVDCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAMKQoMWIoz5V+cTvVu+rAU4GXsrhCHBGSiPluVwE
DwrLa4VmUYcBpKV8bJMmSelbjE8TGtCvIdb3HmrK72ts/9cKIJItgMLEH4DWIO72
F1EW4oYFZ7V4QalK3x5AIk6YCIw+PLYiv+i/C/7z+OwMeOyaPDayPK7bwwBloJHS
/IwHy1eQLqZ58zyCNyjBAmtWQgqP6rLTFG44hRk6jCsHSBuMSe36qs21ZaA3qrui
tRVL2BMIe1+VnudwI+XWhrTaoa5UuZJygE52w7xbGmpv+Q6TapjVPc7s/l7aLBAv
lo/KW3zDWZ8Joj0qftAFWCRI+Qbuw8GR6lvkp7vm85ymUd9nS/Izo0iEsDyppED/
CuG0+n+y7CfGlZ6PqKM0WOeG856oH/BbuMrhPZ68w2S/0tgLFWcOLwFkBJubVTFW
5sWrYmgpxtdjj+8fpFmxstPXOA3DOt6NTEUOeT2xFYn323FpsQm+LV6tTzUcl/T2
ud9dw0ede5ucxI6caLR3MvaChqErUyZF0F09x3sKkedP8tHNutsvEjtgnkhTlypG
Fh+clAPFPJlwTFkp9VB2ULa7giOq8+iEqj7LApB1tp/vgR1qAxTNhWTJpegdrfjF
vLO+ApY0a6NNxKjXe19pPx32YWuGcGOp8At1KRTvBrW1qWlrUn6j99SDcTHjEwmV
54nHAgMBAAGjggEEMIIBADAdBgNVHQ4EFgQUR8qRudhBHPfA4cUWUD454S+L8jUw
DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRHypG52EEc98DhxRZQPjnhL4vy
NTBeBgNVHSAEVzBVMFMGBCtMLwEwSzBJBggrBgEFBQcCARY9aHR0cDovL3d3dy5j
YXJ0YWlkZW50aXRhLmludGVybm8uZ292Lml0L3BvbGljeS9yb290Y2FfY3BzLnBk
ZjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vbGRhcC5jaWUuaW50ZXJuby5nb3Yu
aXQvY2llcm9vdGNhLmNybDAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQAD
ggIBAHzFm/7B4+D1bJWUM38mL2UD6SNr11RVm9ohHPx586rb9tDiea7wgTWBBLyZ
WpdbDWQfSU+13kSsMUvZH60Fg/A95WKrIGo29fjFdHkJrrJm0Tc9CcMLLULWyQBy
oJAv/01NYykGzdgyAJbdkvWTihhlZBpFZ2GMQT4g099Xd6iWXiEaKcDDMh9o8PU0
fZy0L274HE6ql5P5xdiqfv3dyiEM+eZ5OEMKOkkJPtlXX/H20g0AkUZpFlfqC6mh
uEad28YH3OlTJyl7sEYNPqjEp9UvcdD9XpAVr/GxGHf96H4Ozqu9ZQFCG6E5aMMY
XOxhXHNnRpnwkao1edaomxJTDtcDSdFE7Bp0fKRUpSVUpLbYcAda0/kgl7s/bZQl
xZKNhSqOZuQA91LKYB3CwXEHblJP9j45Em86J0rwfpB28Cb9ePNCkHaoSkJ25PtK
zNgKtikkGZCMmYpdiyQELuoBZHtxJ+Jo3tmc6Wy9WF9FzPYyKrC1d+NJdF8477zC
pXk8l5z5zDoFt5H30Xdz9x+toehpemDABBvbNd+jSfwpay6O7qr8cnr7O+9uBrzK
Yv5yjgxBQ7KVF367aEXYdplSzJzlj+dl/sqHzyeTcw7CaMptYy5XW9JbmkvaxWX2
vK8/rpnLv9Y9hX1KmmFMAK3PXgTw8Bym3+nM8Qc76Sx/LOHL
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG7jCCBNagAwIBAgIIRs2LVrWtjRswDQYJKoZIhvcNAQELBQAwgasxQjBABgNV
BAMMOU5hdGlvbmFsIHJvb3QgQ0EgZm9yIHRoZSBJdGFsaWFuIEVsZWN0cm9uaWMg
SWRlbnRpdHkgQ2FyZDE3MDUGA1UECwwuRGlyZXouIENlbnRyLiBwZXIgaSBTZXJ2
aXppIERlbW9ncmFmaWNpIC0gQ05TRDEfMB0GA1UECgwWTWluaXN0ZXJvIGRlbGwn
SW50ZXJubzELMAkGA1UEBhMCSVQwHhcNMTYwNjA2MTYxNjQxWhcNMzEwNjAzMTYx
NjQxWjCBsjFJMEcGA1UEAwxASXNzdWluZyBzdWIgQ0EgZm9yIHRoZSBJdGFsaWFu
IEVsZWN0cm9uaWMgSWRlbnRpdHkgQ2FyZCAtIFNVQkNBMTE3MDUGA1UECwwuRGly
ZXouIENlbnRyLiBwZXIgaSBTZXJ2aXppIERlbW9ncmFmaWNpIC0gQ05TRDEfMB0G
A1UECgwWTWluaXN0ZXJvIGRlbGwnSW50ZXJubzELMAkGA1UEBhMCSVQwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC3Sk0E2bwMzrp2oRZ52be8Z37f8osu
LwKHt4PTysD+lHyGi3/P37omXUzZewZ/SuSkDY0LzgloMjqiZdfVvobQ/rN+ICwg
cfB6Kf2fFPqN1mPTeJLI537kemkN/qwHIZO+HOlmklY+nJ/HrlVQJ6dxrfd8hWLp
XR4L2yTtqhB2bMrZGN+EtsiML8DetRM/i4/AV5UYTOrWEbexnKgwwATu9TgDSk+f
lqwB6R24islNbfDlnmm+XXaaba3Jflajk5vAt8cYyVkYx6QCwVDbifHWEG52z7GW
XD/TkDIV2FPm6qTCQdBPfEbmXfTpIcu8sN+gIQMlb/fbcsqi9liw26pxO4RlvO7K
74GbcTgUY4q7iG+SzNkXXLXRDlLsjloA+y3j/TPM0RwBSsnYghDrcxyq8KXNuKk6
JXtv5N68Qttr+SVYhE3EvMUeUJqgp1s1siDKswcuIasl07HlcgYZVC6joEg9xlEX
IcCMFibyNIjrm+oybA1srZ9lqf+14Z9ERGacJJTGy3Mkl7UxWNBeyK3DT15j8pZY
wVIvJBfNX8x+r59huVQCOqxwvCe2AHIAqPkuLSjqVFFek8q6l2az3mcY2mgE8Avu
Du6rilJEq2ZU3sGBM3ep7yuKZErwlU0sXlqxMvoDe44/rU8Puan+4/OI9+VDaHi4
P6RxTTcU4DkQfwIDAQABo4IBCzCCAQcwHQYDVR0OBBYEFOJDidPiBHX9JjL5SkxB
3NmJPuTBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUR8qRudhBHPfA
4cUWUD454S+L8jUwYgYDVR0gBFswWTBXBgQrTC8CME8wTQYIKwYBBQUHAgEWQWh0
dHA6Ly93d3cuY2FydGFpZGVudGl0YS5pbnRlcm5vLmdvdi5pdC9wb2xpY3kvc3Vi
Y2FfYXV0aF9jcHMucGRmMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9sZGFwLmNp
ZS5pbnRlcm5vLmdvdi5pdC9jaWVzdWJjYTEuY3JsMA4GA1UdDwEB/wQEAwIBhjAN
BgkqhkiG9w0BAQsFAAOCAgEAD+TJp+WNJQFfyCzlmPKNXsUTHiARHgLp5u08Rm5j
DO1ffSp3YAWQ0u4BIy5HzCRxnQReJcDe3sR+dxnAh+6DW69pu5zxJkBNhgw+J7mG
izyQ7moHxMZeYGMgKSGzHOQp84OA7vb2km4J8U90iJIEbfWo1o0qrFoFlyW/Xsts
wevyy7/G6uGccomwuJS/oklw1Jx8jIxAD+4KPfhg7MEO1Ae8CJ2i4bQdK+oRpCMH
Mxog23C9Ry3AqNRyQDn4HQ7gk2MgxlOjxfdrYE6u1YtV2mliBoOVmI6U10BzsqK5
mKbj+mNVG0wTTNlIbeqqQsnGqA2D2XA/l0p8gGG0dnjK+Y1bishGX9nI6c868r24
WYu1Xjw2XgjFeJzyL78iOVDxyewRjpgZhEuIo/DPyW/SkMH4JkvABa/CmNIe3Eua
E1/SkXMePWG73ZOmh4cytQ8yyMNviUqU274EQMhtWx3XFvfDB0eu+E9u3S5dqVaa
nArroE60WFp/Bl2dNDHJgis3CewlZLbCRxc4rH0g8Ipfqe0Wte9uvhLZhColvbZ/
SEXCp2yUzFp3UYmsmRxyVlcFGwDF4/6ZXXhsrWTH/0jV8Or9zV598Tv7Lo5gz7IA
+GI2BpZd96tz2+ItNxLdRl0ZVavpJYeL/6dQ/OyHUnGJrSJUq/3BKLtOgMTmEOpX
RUE=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG8DCCBNigAwIBAgIIbidwj1LWzEAwDQYJKoZIhvcNAQELBQAwgasxQjBABgNV
BAMMOU5hdGlvbmFsIHJvb3QgQ0EgZm9yIHRoZSBJdGFsaWFuIEVsZWN0cm9uaWMg
SWRlbnRpdHkgQ2FyZDE3MDUGA1UECwwuRGlyZXouIENlbnRyLiBwZXIgaSBTZXJ2
aXppIERlbW9ncmFmaWNpIC0gQ05TRDEfMB0GA1UECgwWTWluaXN0ZXJvIGRlbGwn
SW50ZXJubzELMAkGA1UEBhMCSVQwHhcNMjAwNTI1MDYxNDMyWhcNMzUwNTIyMDYx
NDMyWjCBtDFLMEkGA1UEAwxCSXNzdWluZyBzdWIgQ0EgZm9yIHRoZSBJdGFsaWFu
IEVsZWN0cm9uaWMgSWRlbnRpdHkgQ2FyZCAtIFNVQkNBMDAyMTcwNQYDVQQLDC5E
aXJlei4gQ2VudHIuIHBlciBpIFNlcnZpemkgRGVtb2dyYWZpY2kgLSBDTlNEMR8w
HQYDVQQKDBZNaW5pc3Rlcm8gZGVsbCdJbnRlcm5vMQswCQYDVQQGEwJJVDCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJl0P3lxsxXbmvW/i6b4HOrzEzSw
mkmjhWcCgm8zykHw5Zm9yA8ex3fhsPTQaw/to1T2183kapcg/lnXnR2Rx5v3VvvR
JODs6kMzWIQ/elJjguitlsPrjmjgsIXYBI+Re8ITHP0J783jHhWM7kbhJ8XAjk39
mhX/NFx6mLgOBqdep/QAkldV8s2EApodclvdB42QfrkPd3yWZmo7jP5Jp5QJ5Lms
ThWXCmXKCPcAiXY1Z/NFWK32DmjrabBRJm2YyvOsXQVjiyjYjowwVIG0UeF0ZGBC
F0Wd7jjIghyivTi/hMWXOy++XsfmgCS5GD6ylnsSP+vJXmOFS6aINkTpUlfYHw35
VRU9RFIt9qunKaLJA+BgvHZxGLcfhe6mveLalunCH7KLip0oVDO5qw2/ct5kX/Pl
cDlGI97eWWI2EsHmaHeHns++n1RuRRpmHlF5cb92dF3ciFKgmkVKK3xHlG+j0++A
usJMKOSJZl2n8vL2YzeCWWcbidZeze/q5Mq0H+snRTKq9dnjfwln+81Fvh9GjtWv
iDgJ/Trd6CRrMEUhbCi3drpVvYTT2na9HVikLD44CurZgcOYCaPlf47hjKQwNT0d
BtvZdF6ThwJz9HFOTMHUTiaXD4vEC6kLRnAA1nL7ticLN7MfRECMK+/8c8hgHUe5
RB1DXiYfTus2WOGzAgMBAAGjggELMIIBBzAdBgNVHQ4EFgQU+S7pCGSforgrqDKV
QXPpfZ0MFRgwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRHypG52EEc
98DhxRZQPjnhL4vyNTBiBgNVHSAEWzBZMFcGBCtMLwIwTzBNBggrBgEFBQcCARZB
aHR0cDovL3d3dy5jYXJ0YWlkZW50aXRhLmludGVybm8uZ292Lml0L3BvbGljeS9z
dWJjYV9hdXRoX2Nwcy5wZGYwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2xkYXAu
Y2llLmludGVybm8uZ292Lml0L2NpZXJvb3RjYS5jcmwwDgYDVR0PAQH/BAQDAgGG
MA0GCSqGSIb3DQEBCwUAA4ICAQBVmLny00jZq9Zop2SfljcgUtZ2WAZVUcI1tsXb
NRKsarhgqg1G3HKv9jufqxYoL+gfAOa5jRoPmqvWGuSBzM9fSMu8bURDdSljoTos
4OR+8hgEYz4NoDTHqyXxXgwGVcGRSz8jppFUQOFur9yScx+mGY1XPGiO3FBDwROu
2jhIT3eFBbTq0369lP2GI+qAgIkeoggjwR1u1WNasoCDeLViDOrWvSOB3/FPQIhG
VWhsJnIGq8zJQGfuo/P8ae33CleB69aZIsR3TuPQ17tWg5zG6Zbq7f/9p02pTm6E
rj0TLtPJqMoPLloW/LmO5EfB9BcTYT187vogjZ3M/ulrSM/Zm4bb3zHgPBNRY0Nl
27Mw7E9swaCXeIJySLGv/aS4o4cNqkFDJH5btrDrShQBGD9ANi77LlSlEQ4FmzY1
X4UZk5enWQ1A/uOylLrtfG3puXcekdcxTneCdkbAr+yo83Pzba/ZX7kec/tmnoL8
QfPFAbrQx2wnxK9AmxQmvxwAm9GmkRIe8TFgAWODIPiA/rRMVI2TvI37xGWWFZNO
xkgPY5uSajZuOArTrjDUGHqalKQSksylIZ65i4sUXsHGNyH0OFt7ZYAfC0YIl+f6
2yF2MwtqVv7bZB/GF7vb1JZGj9hqTUGVRjz0MFruMBsMhhAUUykCTegIq5C/MFcC
aJQEPQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG8DCCBNigAwIBAgIIJJZNjbfc1rcwDQYJKoZIhvcNAQELBQAwgasxQjBABgNV
BAMMOU5hdGlvbmFsIHJvb3QgQ0EgZm9yIHRoZSBJdGFsaWFuIEVsZWN0cm9uaWMg
SWRlbnRpdHkgQ2FyZDE3MDUGA1UECwwuRGlyZXouIENlbnRyLiBwZXIgaSBTZXJ2
aXppIERlbW9ncmFmaWNpIC0gQ05TRDEfMB0GA1UECgwWTWluaXN0ZXJvIGRlbGwn
SW50ZXJubzELMAkGA1UEBhMCSVQwHhcNMjQwNTE2MTQwMzM3WhcNMzkwNTEzMTQw
MzM3WjCBtDFLMEkGA1UEAwxCSXNzdWluZyBzdWIgQ0EgZm9yIHRoZSBJdGFsaWFu
IEVsZWN0cm9uaWMgSWRlbnRpdHkgQ2FyZCAtIFNVQkNBMDAzMTcwNQYDVQQLDC5E
aXJlei4gQ2VudHIuIHBlciBpIFNlcnZpemkgRGVtb2dyYWZpY2kgLSBDTlNEMR8w
HQYDVQQKDBZNaW5pc3Rlcm8gZGVsbCdJbnRlcm5vMQswCQYDVQQGEwJJVDCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAM+DgWkGOnWDMPtesNeqhW62p2ch
jnx181XY1iJ88rYVQj9ptLGFibURGbAFaSJ1uCniSxrMPByliDkadHkxMjTr+9te
Zu3kPnOoV2pgR78Tn8RLG8BnruX4riuaP1vyKKVFEoO7Td7a075v6i0ipYyZtZ0t
wrtpAD2ZQbrTdUCy3HuWdn0CD7q3YDGskIYfIbFI1R3zgpxM4wSbCO5bqSxiyk2i
MDbm/cQ/b0eX8shXdNhNPrN/imR4w1rZwzSp0JNH1Madf3D9YdAUDUTCQG405lVL
4ha0pUlG+g0Ig0BHDLxBAO6iZ7CZY+YcgV945FqosiBrH1Y8PFmN1VBlFKn351hZ
OAfgnLj1Y6gGgLz2+WUNWZpGDfdPhODWhmffqzeTGihuOgIzfQG3wL1uQ6aeTqQk
cDECs/Tll6lQW6WVqUdFGw8h4hHKHdAizTDi+/vYlGYUceuNCYM+woE+Omvwo8+1
BcqFpVO0YAxlmzVl/HN8kRvoaiwIy6XH5GON0I8aPSFsCqXl0tou8llpdueI6R33
COn6r7O3VjQNXJEpUesHpi9vTuIPaP9W4OCRO9wjrIot6QtmQKTpoN0tpdDsMLdQ
5//zdRG8D4qz3dH0kFEqr5li1rXOUnK79SAygYkdLuD7PRFUyUkVuAbMrn/snLAG
LaUpx0FtcpzQHQojAgMBAAGjggELMIIBBzASBgNVHRMBAf8ECDAGAQH/AgEAMB8G
A1UdIwQYMBaAFEdvJRrD1fP+XjSTEp/YgRXcUgxPMGIGA1UdIARbMFkwVwYEK0wv
AjBPME0GCCsGAQUFBwIBFkFodHRwOi8vd3d3LmNhcnRhaWRlbnRpdGEuaW50ZXJu
by5nb3YuaXQvcG9saWN5L3N1YmNhX2F1dGhfY3BzLnBkZjA9BgNVHR8ENjA0MDKg
MKAuhixodHRwOi8vbGRhcC5jaWUuaW50ZXJuby5nb3YuaXQvY2llcm9vdGNhLmNy
bDAdBgNVHQ4EFgQU+LbUqPVMY/CaGMSqUumS65tDx+EwDgYDVR0PAQH/BAQDAgGG
MA0GCSqGSIb3DQEBCwUAA4ICAQBsWaBdJkl1YU217X4HChaW3PYV0ocii+MFkTwx
DmAKqGXTEWbPZSz00NyHDORMKY/cx0s3eNZ14caed/KBbdgkEfl3Wymq9mWSWnjI
bB39d4L1XalZWOquA6iQMrM3+9Aa/cOwj63rxYeDHjDRwW5OETSk47WTdJoMU3c2
1kbXUSlIX3VgW+8pX5KDEMwQobuIyS2TUpc10DV2MbDDZFeaUePVXD+xuBkCJ4LR
6yXsWdad8NPRX0SK/dtOB0DSdPM7HpNMeurNF6KdxHK3w5rbt0n8n129NmPT4lnx
Aw1U0wZULU29gu9WhadlwbSLxvXSfsh4dLLwyLL4PwjBgIYYGkLt9n/JQD5XF2BM
94LOpdv5VBa6nhaCralW9npc1djK02CgINROFR+rwFhaWPptYZmnMVX0Pw9Qe8X+
Nrml576sJydJCh+Obc/auwbpjW9oTibvdqTeYAk7DGyitOSI3GZSQEccfaWxxcL2
t6hYmMXswMLrG8THL++8D7fBo01kV5V2sdhJ2NdFeKvylGfQBU6kmAGtEkq5EElz
3UhfArjj7d31FBPM6TKEmmMi5vJJ1IqyjxIHfHtRnRFjQadPxjf2Zdo3nsgCvL/5
HjcTFIj2d6ZJIrUMBLX/q/aQRsaEZciEWUDZV9LCfnmEmgPd3YEr5Lqqxt+9Ej7R
t+VL1w==
-----END CERTIFICATE-----
)";

static int load_pem_into_store(X509_STORE* store, const char* pem, size_t len) {
    
    if (!pem || !len) return 0;
    BIO* bio = BIO_new_mem_buf(pem, (int)len);
    if (!bio) return 0;
    int added = 0;
    for (;;) {
        X509* c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (!c) break;
        char subj[512]={0};
        X509_NAME_oneline(X509_get_subject_name(c), subj, sizeof subj);
        
        if (X509_STORE_add_cert(store, c) == 1) added++;
        X509_free(c);
    }
    BIO_free(bio);
    
    return added;
}

static X509_STORE* build_store_with_fallback(const char* ca_file,
                                             const char* ca_path,
                                             const char* extra_ca_pem,
                                             bool cie_only /* NEW: forza CIE-only */)
{
    

    X509_STORE* store = X509_STORE_new();
    if (!store) return nullptr;

    int total_added = 0;
    bool system_ok = false;

    // 1) Se NON è CIE-only, prova (eventualmente) i percorsi passati o quelli di sistema
    if (!cie_only) {
        if (ca_file || ca_path) {
            system_ok = (X509_STORE_load_locations(store,
                           ca_file ? ca_file : nullptr,
                      ca_path ? ca_path : nullptr) == 1);
        }
        if (!system_ok) {
            system_ok = (X509_STORE_set_default_paths(store) == 1);
        }
    }

    // 2) Carica SEMPRE gli eventuali PEM passati in memoria
    if (extra_ca_pem && extra_ca_pem[0]) {
        int n = load_pem_into_store(store, extra_ca_pem, (int)strlen(extra_ca_pem));
        total_added += n;
    }

    // 3) Carica SEMPRE il bundle CIE embedded (Root + SUBCA1 + SUBCA002 + SUBCA003)
    {
        int n = load_pem_into_store(store, kCIE_CA_BUNDLE_PEM, (int)strlen(kCIE_CA_BUNDLE_PEM));
        total_added += n;
    }

    // 4) Se siamo in CIE-only, vogliamo almeno 1 CA dal bundle
    if (cie_only && total_added <= 0) {
        LOG_ERR((0, "chain", "CIE-only store is empty: bundle non caricato"));
        X509_STORE_free(store);
        return nullptr;
    }

    // 5) Se NON siamo in CIE-only e system_ok==false e non abbiamo caricato nulla -> errore
    if (!cie_only && !system_ok && total_added <= 0) {
        LOG_ERR((0, "chain", "store vuoto (no system CA e nessun PEM)"));
        X509_STORE_free(store);
        return nullptr;
    }

    
    return store;
}


// s: "YYMMDDhhmmssZ" o "YYYYMMDDhhmmssZ" -> time_t (best effort, UTC)
static bool parse_asn1_like_utc(const char* s, time_t& out) {
    if (!s || !*s) return false;
    std::string str(s);
    if (!str.empty() && str.back() == 'Z') str.pop_back();
    struct tm t{}; t.tm_isdst = -1;

    if (str.size() == 12) { // YYMMDDhhmmss
        int YY = std::stoi(str.substr(0,2));
        int year = (YY >= 50 ? 1900+YY : 2000+YY);
        t.tm_year = year - 1900;
        t.tm_mon  = std::stoi(str.substr(2,2)) - 1;
        t.tm_mday = std::stoi(str.substr(4,2));
        t.tm_hour = std::stoi(str.substr(6,2));
        t.tm_min  = std::stoi(str.substr(8,2));
        t.tm_sec  = std::stoi(str.substr(10,2));
    } else if (str.size() == 14) { // YYYYMMDDhhmmss
        t.tm_year = std::stoi(str.substr(0,4)) - 1900;
        t.tm_mon  = std::stoi(str.substr(4,2)) - 1;
        t.tm_mday = std::stoi(str.substr(6,2));
        t.tm_hour = std::stoi(str.substr(8,2));
        t.tm_min  = std::stoi(str.substr(10,2));
        t.tm_sec  = std::stoi(str.substr(12,2));
    } else return false;

#if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
    out = timegm(&t);
#else
    time_t local = mktime(&t);
    struct tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &local);
#else
    gmtime_r(&local, &utc);
#endif
    out = local + difftime(mktime(&t), mktime(&utc));
#endif
    return out != (time_t)-1;
}

// API da usare in verify_pdf: restituisce 1=OK, 0=KO
int verify_chain_from_der_at_time(const unsigned char* cert_der, long cert_len,
                                  const char* ca_file,
                                  const char* ca_path,
                                  const char* extra_ca_pem,
                                  const char* verify_time_asn1) {
    const unsigned char* p = cert_der;
    X509* leaf = d2i_X509(nullptr, &p, cert_len);
    if (!leaf) return 0;

    X509_STORE* store = build_store_with_fallback(ca_file, ca_path, extra_ca_pem,true);
    if (!store) { X509_free(leaf); return 0; }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) { X509_STORE_free(store); X509_free(leaf); return 0; }

    if (X509_STORE_CTX_init(ctx, store, leaf, nullptr) != 1) {
        X509_STORE_CTX_free(ctx); X509_STORE_free(store); X509_free(leaf);
        return 0;
    }

    if (verify_time_asn1 && verify_time_asn1[0]) {
        time_t tt{};
        if (parse_asn1_like_utc(verify_time_asn1, tt)) {
            X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(ctx), tt);
        }
    }
    // Se vuoi forzare uno scopo: X509_VERIFY_PARAM_set_purpose(...)

    int ok = X509_verify_cert(ctx);
    if (!ok) {
        int err = X509_STORE_CTX_get_error(ctx);
    } else {
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    return ok == 1 ? 1 : 0;
}
int get_file_type(char* szFileName);
long verifyTST(CTimeStampToken& tst, TS_INFO* pTSInfo, BOOL bVerifyCRL);

long verify_signed_document(DISIGON_VERIFY_CONTEXT* pContext, CSignedDocument& sd, VERIFY_INFO* pVerifyInfo);
long verify_pdf(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_p7m(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_tsd(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_tst(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_tsr(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_m7m(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_xml(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo);
long verify_pdf(DISIGON_VERIFY_CONTEXT* pContext, UUCByteArray& data, VERIFY_INFO* pVerifyInfo);


long sign_pdf(DISIGON_SIGN_CONTEXT* pContext, UUCByteArray& data);
long sign_xml(DISIGON_SIGN_CONTEXT* pContext, UUCByteArray& data);


//long load_tsl(const char* szTSLUrl, const char* szCACertDir);

long HTTPRequest(UUCByteArray& data, const char* szUrl, const char* szContentType, UUCByteArray& response);

static xmlChar nl[] = "\n";

char* FILETYPE[] = {"PKCS7 file", "PDF file", "M7M file", "TSR file", "TST file", "TSD file", "XML file"};


long disigon_set(int option, void* value)
{
    switch(option)
    {
    
    case DISIGON_OPT_CACERT_DIR:
        LOG_DBG((0, "disigon_set", "set DISIGON_OPT_CACERT_DIR: %s", (char*)value));
        strcpy(g_szCACertDir, (char*)value);
        g_bCACertDirSet = true;
        break;

    
    case DISIGON_OPT_LOG_FILE:
        SET_LOG_FILE((char*)value);
        break;

    case DISIGON_OPT_LOG_LEVEL:
        SET_LOG_LEVEL((long)value);
        break;

    case DISIGON_OPT_OID_MAP_FILE:
        {
            LOG_DBG((0, "disigon_set", "DISIGON_OPT_OID_MAP_FILE: %s", (char*)value));
            long nRet = g_mapOIDProps.load((char*)value);
            if(nRet)
                return nRet;
        }
        break;
    }

    return 0;
}

long disigon_set_int(int option, int value)
{
    return disigon_set(option, (void*)value);
}

/*
long disigon_set_bool(int option, bool value)
{
    return disigon_set(option, (void*)value);
}
*/
long disigon_set_string(int option, char* value)
{
    return disigon_set(option, (void*)value);
}


void disigon_cleanup()
{
    CCertStore::CleanUp();
}

DISIGON_CTX disigon_sign_init(void)
{
    LOG_MSG((0, "--> disigon_sign_init", ""));

#ifdef WIN32
    //checkLicense();
#endif
    
    DISIGON_SIGN_CONTEXT* pContext = new DISIGON_SIGN_CONTEXT;
    
    pContext->bDetached = 0;
    pContext->bVerifyCert = DEFAULT_VERIFY_USER_CERT;
    pContext->nInputFileType = DISIGON_FILETYPE_PLAINTEXT;
    strcpy(pContext->szPdfSubfilter, DISIGON_PDF_SUBFILTER_PKCS_DETACHED);
    pContext->szOutputFile[0] = 0;
    pContext->szInputFile[0] = 0;
    pContext->szPdfLocation[0] = NULL;
    pContext->szPdfReason[0] = NULL;
    pContext->szPdfName[0] = NULL;
    pContext->szPIN[0] = NULL;
    pContext->nSlot = -1;
    pContext->nHashAlgo = CKM_SHA256_RSA_PKCS;
    pContext->fPdfBottom = 0;
    pContext->fPdfLeft = 0;
    pContext->fPdfWidth = 0;
    pContext->fPdfHeight = 0;
    pContext->nPdfPage = 0;
    pContext->szPdfImagePath[0] = 0;
    pContext->szPdfDescription[0] = 0;
    strcpy(pContext->szPdfLocationLabel, "Signed by:");
    strcpy(pContext->szPdfReasonLabel, "Reason:");
    strcpy(pContext->szPdfLocationLabel, "Location:");
    pContext->szAlias[0] = 0;
    pContext->szTSAUrl[0] = 0;
    pContext->szTSAUsername[0] = 0;
    pContext->szTSAPassword[0] = 0;
    pContext->bCades = false;
    pContext->pSignatureGenerator = NULL;
    pContext->pIAS = NULL;
    
    if(g_mapOIDProps.size() == 0)
        g_mapOIDProps.load("OID.txt");

//    if (g_bCACertDirSet && CCertStore::m_certMap.size() == 0)
//    {
//        long nRet = CCertStore::LoadCertificates(g_szCACertDir);
//        if (nRet)
//            LOG_ERR((0, "disigon_sign_init", "set DISIGON_OPT_CACERT_DIR error: %X", nRet));
//        else
//            LOG_DBG((0, "disigon_sign_init", "set DISIGON_OPT_CACERT_DIR: OK"));
//    }

    LOG_MSG((0, "<-- disigon_sign_init", "Context: %p", pContext));

    return (DISIGON_CTX) pContext;
}

long disigon_sign_set_int(DISIGON_CTX ctx, int option, int value)
{
    return disigon_sign_set(ctx, option, (void*)value);
}

/*
long disigon_sign_set_bool(DISIGON_CTX ctx, int option, bool value)
{
    return disigon_sign_set(ctx, option, (void*)value);
}
*/
long disigon_sign_set_string(DISIGON_CTX ctx, int option, char* value)
{
    return disigon_sign_set(ctx, option, (void*)value);
}



long disigon_sign_set(DISIGON_CTX ctx, int option, void* value)
{
    LOG_MSG((0, "--> disigon_sign_set", "Context: %p, Option: %d", ctx, option));

    long nRet = 0;

    __TRY

    DISIGON_SIGN_CONTEXT* pContext = (DISIGON_SIGN_CONTEXT*)ctx;

    switch(option)
    {
        
    case DISIGON_OPT_IAS_INSTANCE:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_IAS_INSTANCE", (char*)value));
        pContext->pIAS = (IAS*)value;
        break;

    case DISIGON_OPT_PIN:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PIN", "****"));
        strcpy(pContext->szPIN, (char*)value);
        break;

    case DISIGON_OPT_ALIAS:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_ALIAS", (char*)value));
        strcpy(pContext->szAlias, (char*)value);
        //pContext->pSignatureGenerator->SetAlias((char*)value);
        break;

    case DISIGON_OPT_CADES:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %d", ctx, "DISIGON_OPT_CADES", (long)value));
        //pContext->pSignatureGenerator->SetCAdES((BOOL)(long)value);
        pContext->bCades = (BOOL)(long)value;
        break;

    case DISIGON_OPT_INPUTFILE:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_INPUTFILE", (char*)value));
        strcpy(pContext->szInputFile, (char*)value);
        break;

    case DISIGON_OPT_OUTPUTFILE:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_OUTPUTFILE", (char*)value));
        strcpy(pContext->szOutputFile, (char*)value);
        break;

    case DISIGON_OPT_INPUTFILE_TYPE:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %d", ctx, "DISIGON_OPT_INPUTFILE_TYPE", (long)value));
        pContext->nInputFileType = (long)value;
        break;

    case DISIGON_OPT_DETACHED:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %d", ctx, "DISIGON_OPT_DETACHED", (long)value));
        pContext->bDetached = (BOOL)(long)value;
        break;

    case DISIGON_OPT_TSA_URL:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_TSA_URL", (char*)value));
        strcpy(pContext->szTSAUrl, (char*)value);
        //pContext->pSignatureGenerator->SetTSA((char*)value, NULL, NULL);
        break;

    case DISIGON_OPT_TSA_USERNAME:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_TSA_USERNAME", (char*)value));
        strcpy(pContext->szTSAUsername, (char*)value);
        //pContext->pSignatureGenerator->SetTSAUsername((char*)value);
        break;

    case DISIGON_OPT_TSA_PASSWORD:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_TSA_PASSWORD", (char*)value));
        strcpy(pContext->szTSAPassword, (char*)value);
        //pContext->pSignatureGenerator->SetTSAPassword((char*)value);
        break;

    case DISIGON_OPT_PDF_SUBFILTER:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_SUBFILTER", (char*)value));
        strcpy(pContext->szPdfSubfilter, (char*)value);
        break;

    case DISIGON_OPT_PDF_LOCATION:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_LOCATION", (char*)value));
        strcpy(pContext->szPdfLocation, (char*)value);
        break;

    case DISIGON_OPT_PDF_NAME:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_NAME", (char*)value));
        strcpy(pContext->szPdfName, (char*)value);
        break;

    case DISIGON_OPT_PDF_REASON:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_REASON", (char*)value));
        strcpy(pContext->szPdfReason, (char*)value);
        break;

    case DISIGON_OPT_PDF_BOTTOM:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %f", ctx, "DISIGON_OPT_PDF_BOTTOM", *(float*)value));
        pContext->fPdfBottom = *((float*)value);
        break;

    case DISIGON_OPT_PDF_LEFT:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %f", ctx, "DISIGON_OPT_PDF_LEFT", *((float*)value)));
        pContext->fPdfLeft = *((float*)value);
        break;

    case DISIGON_OPT_PDF_WIDTH:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %f", ctx, "DISIGON_OPT_PDF_WIDTH", *((float*)value)));
        pContext->fPdfWidth = *((float*)value);
        break;

    case DISIGON_OPT_PDF_HEIGHT:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %f", ctx, "DISIGON_OPT_PDF_HEIGHT", *((float*)value)));
        pContext->fPdfHeight = *((float*)value);
        break;

    case DISIGON_OPT_PDF_PAGE:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %d", ctx, "DISIGON_OPT_PDF_PAGE", *((long*)value)));
        pContext->nPdfPage = *((long*)value);
        break;

    case DISIGON_OPT_PDF_IMAGEPATH:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_IMAGEPATH", (char*)value));
        strcpy(pContext->szPdfImagePath, (char*)value);
        break;

    case DISIGON_OPT_PDF_DESCRIPTION:
        LOG_MSG((0, "digitsign_sign_setopt", "Context: %p, Option: %s, Value: %s", ctx, "DIGITSIGN_OPT_PDF_DESCRIPTION", (char*)value));
        strcpy(pContext->szPdfDescription, (char*)value);
        break;

    case DISIGON_OPT_PDF_LOCATION_LABEL:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_LOCATION_LABEL", (char*)value));
        strcpy(pContext->szPdfLocationLabel, (char*)value);
        break;

    case DISIGON_OPT_PDF_NAME_LABEL:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_NAME_LABEL", (char*)value));
        strcpy(pContext->szPdfNameLabel, (char*)value);
        break;

    case DISIGON_OPT_PDF_REASON_LABEL:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_PDF_REASON_LABEL", (char*)value));
        strcpy(pContext->szPdfReasonLabel, (char*)value);
        break;

    case DISIGON_OPT_VERIFY_USER_CERTIFICATE:
        LOG_MSG((0, "disigon_sign_set", "Context: %p, Option: %s, Value: %s", ctx, "DISIGON_OPT_VERIFY_USER_CERTIFICATE", (char*)value));
        pContext->bVerifyCert = (BOOL)(long)value;
        break;
    }

    LOG_MSG((0, "<-- disigon_sign_set", "Returns %x", nRet));

    return nRet;

    __CATCH
}

void disigon_sign_freecertificates(CERTIFICATES* pCerts)
{
    for(int i = 0; i < pCerts->nCount; i++)
    {
        CERTIFICATE cert = pCerts->pCertificate[i];
        SAFEDELETE(cert.pCertificate);
    }
}

long disigon_sign_sign(DISIGON_CTX ctx)
{
    LOG_MSG((0, "--> disigon_sign_sign", "Context: %p", ctx));

//    char szv[200];
//    GetVersionString(szv);

//    LOG_MSG((0, "disigon_sign_sign", "Version: %s", szv));
    LOG_MSG((0, "disigon_sign_sign", "Version: %s", "1.0.0"));


    __TRY

    DISIGON_SIGN_CONTEXT* pContext = (DISIGON_SIGN_CONTEXT*)ctx;
    
	LOG_MSG((0, "--> disigon_sign_sign", "pContext: %p, pdf_left: %f", pContext, pContext->fPdfLeft));
    if(pContext->szInputFile[0] == 0)
    {
        //LOG_ERR((0, "disigon_sign_sign", "Context: %p, Error: DISIGON_ERROR_INVALID_FILE"));
		LOG_ERR((0, "disigon_sign_sign -> Error: DISIGON_ERROR_INVALID_FILE", ""));
        return DISIGON_ERROR_INVALID_FILE;
    }

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- disigon_sign_sign", "Context: %p, Error: %x, file: %s", pContext, DISIGON_ERROR_FILE_NOT_FOUND, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);

    LOG_DBG((0, "disigon_sign_sign", "Context: %p, Load P11", pContext));

    long nRes = 0;
    
    if(pContext->pIAS)
    {
        CCIESigner* pCIESigner = new CCIESigner(pContext->pIAS);
        long ret = pCIESigner->Init(pContext->szPIN);
        
        LOG_DBG((0, "CIESigner::Init", "ret %x", ret));
        
        if(ret != 0)
        {
            delete pCIESigner;
            pContext->pSigner = NULL;
            pContext->pSignatureGenerator = NULL;
            return ret;
        }
        
        pContext->pSigner = pCIESigner;
        pContext->pSignatureGenerator = new CSignatureGenerator(pContext->pSigner);
        
        LOG_DBG((0, "CIESigner::Init", "OK"));
        
    }

    if(pContext->szTSAUrl[0])
        pContext->pSignatureGenerator->SetTSA(pContext->szTSAUrl, NULL, NULL);

    if(pContext->szTSAUsername[0])
        pContext->pSignatureGenerator->SetTSAUsername(pContext->szTSAUsername);

    if(pContext->szTSAPassword[0])
        pContext->pSignatureGenerator->SetTSAPassword(pContext->szTSAPassword);
    
    if(pContext->szAlias[0])
        pContext->pSignatureGenerator->SetAlias(pContext->szAlias);

    pContext->pSignatureGenerator->SetCAdES(pContext->bCades);
    
    int nFileType = pContext->nInputFileType;

    if(nFileType == DISIGON_FILETYPE_AUTO)
        nFileType = get_file_type(pContext->szInputFile);
	LOG_MSG((0, "--> disigon_sign_sign", "pContext: %p, pdf_left: %f", pContext, pContext->fPdfLeft));
    if(nFileType == DISIGON_FILETYPE_PDF)
    {
        nRes = sign_pdf(pContext, data);
        return nRes;
    }
    else if(nFileType == DISIGON_FILETYPE_P7M)
    {
        pContext->pSignatureGenerator->SetPKCS7Data(data);
    }
    else if(nFileType == DISIGON_FILETYPE_XML)
    {
        nRes = sign_xml(pContext, data);
        return nRes;
    }
    else
    {
        LOG_DBG((0, "disigon_sign_sign", "Context: %p, SetData", pContext));
        pContext->pSignatureGenerator->SetData(data);
    }

    UUCByteArray signature;

    LOG_DBG((0, "disigon_sign_sign", "Context: %p, Sign", pContext));

    nRes = pContext->pSignatureGenerator->Generate(signature, pContext->bDetached, pContext->bVerifyCert);
    if(nRes)
    {
        LOG_ERR((0, "<-- disigon_sign_sign", "Context: %p, Error: %x", pContext, nRes));
        return nRes;
    }

    if(pContext->szOutputFile[0] == 0)
    {
        sprintf(pContext->szOutputFile, "%s.p7m",  pContext->szInputFile);
    }

    LOG_DBG((0, "disigon_sign_sign", "Context: %p, Outputfile: %s", pContext, pContext->szOutputFile));

    f = fopen(pContext->szOutputFile, "w+b");
    if(!f)
    {
        LOG_ERR((0, "<-- disigon_sign_sign", "Context: %p, Error: %x, file: %s", pContext, DISIGON_ERROR_FILE_NOT_FOUND, pContext->szOutputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    fwrite(signature.getContent(), 1, signature.getLength(), f);

    fclose(f);

    LOG_DBG((0, "<-- disigon_sign_sign", "Context: %p", pContext));
    
    return 0;

    __CATCH
}

long disigon_sign_cleanup(DISIGON_CTX ctx)
{
    LOG_MSG((0, "--> disigon_sign_cleanup", "Context: %p", ctx));

    __TRY

    DISIGON_SIGN_CONTEXT* pContext = (DISIGON_SIGN_CONTEXT*)ctx;

    
    try
    {
        if(pContext->pSigner)
            pContext->pSigner->Close();
    }
    catch(...)
    {

    }
    
    SAFEDELETE(pContext->pSigner);
    SAFEDELETE(pContext->pSignatureGenerator);

    SAFEDELETE(pContext);

    return 0;

    __CATCH
}
 

DISIGON_CTX disigon_verify_init(void)
{
    LOG_MSG((0, "--> disigon_verify_init", ""));

/*
    #ifdef WIN32
        checkLicense();
    #endif
*/
    DISIGON_VERIFY_CONTEXT* pContext = new DISIGON_VERIFY_CONTEXT;

    pContext->szOutputFile[0] = '\0';
    pContext->bVerifyCRL = 0;
    pContext->nInputFileType = DISIGON_FILETYPE_AUTO;
    pContext->szInputPlainTextFile[0] = '\0';
    //pContext->szPdfSubfilter[0] = '\0';
    pContext->szOutputFile[0] = 0;
    pContext->szInputFile[0] = 0;

	memset(g_szVerifyProxy, 0, MAX_PATH);
	
	if (g_szVerifyProxyUsrPass)
	{
		g_szVerifyProxyUsrPass = NULL;
	}
	

	g_nVerifyProxyPort = -1;

//    if(g_mapOIDProps.size() == 0)
//        g_mapOIDProps.load("OID.txt");

//    if(g_bCACertDirSet && CCertStore::m_certMap.size() == 0)
//    {
//        long nRet = CCertStore::LoadCertificates(g_szCACertDir);
//        if(nRet)
//            LOG_ERR((0, "disigon_verify_init", "set DISIGON_OPT_CACERT_DIR error: %X", nRet));
//        else
//            LOG_DBG((0, "disigon_verify_init", "set DISIGON_OPT_CACERT_DIR: OK"));
//    }

    LOG_MSG((0, "<-- disigon_verify_init", "Context: %p", pContext));

    return (DISIGON_CTX)pContext;
}

long disigon_verify_set_int(DISIGON_CTX ctx, int option, int value)
{
    return disigon_verify_set(ctx, option, (void*)value);
}

long disigon_verify_set_string(DISIGON_CTX ctx, int option, char* value)
{
    return disigon_verify_set(ctx, option, (void*)value);
}

long disigon_verify_set(DISIGON_CTX ctx, int option, void* value)
{
    LOG_MSG((0, "--> disigon_verify_set", "Context: %p", ctx));

    __TRY

    DISIGON_VERIFY_CONTEXT* pContext = (DISIGON_VERIFY_CONTEXT*)ctx;

    switch(option)
    {
        
    case DISIGON_OPT_INPUTFILE:
        strcpy(pContext->szInputFile, (char*)value);
        break;
 
    case DISIGON_OPT_OUTPUTFILE:
        strcpy(pContext->szOutputFile, (char*)value);
        break;

    case DISIGON_OPT_VERIFY_REVOCATION:
        LOG_DBG((0, "disigon_verify_set", "Revocation: %d", (long)value));
        pContext->bVerifyCRL = (BOOL)(long)value;
        break;

    case DISIGON_OPT_INPUTFILE_PLAINTEXT:
        strcpy(pContext->szInputPlainTextFile, (char*)value);
        break;

    case DISIGON_OPT_INPUTFILE_TYPE:
        pContext->nInputFileType = (long)value;
        break;

		case DISIGON_OPT_PROXY:
		strcpy(g_szVerifyProxy, (char*)value);
		LOG_DBG((0, "disigon_verify_set", "Proxy: %s", g_szVerifyProxy));
		if (g_nVerifyProxyPort == -1)
			g_nVerifyProxyPort = 0;
		break;

	case DISIGON_OPT_PROXY_USRPASS:
		g_szVerifyProxyUsrPass = (char*)value;
		LOG_DBG((0, "disigon_verify_set", "ProxyUsrPass: %s", g_szVerifyProxyUsrPass));
		break;

	case DISIGON_OPT_PROXY_PORT:
		g_nVerifyProxyPort = (long)value;
		LOG_DBG((0, "disigon_verify_set", "ProxyPort: %d", g_nVerifyProxyPort));
		break;
    }

    return 0;
    
    __CATCH
}


long disigon_verify_verify(DISIGON_CTX ctx, VERIFY_RESULT* pVerifyResult)
{
    LOG_MSG((0, "--> disigon_verify_verify", "Context: %p", ctx));

    __TRY

    DISIGON_VERIFY_CONTEXT* pContext = (DISIGON_VERIFY_CONTEXT*)ctx;

    if(pContext->szInputFile[0] == 0)
    {
        LOG_ERR((0, "disigon_verify_verify", "Context: %p, Error: DISIGON_ERROR_INVALID_FILE"));
        return DISIGON_ERROR_INVALID_FILE;
    }

    pVerifyResult->verifyInfo.pSignerInfos = NULL;
    pVerifyResult->verifyInfo.pTSInfo = NULL;


    int nFileType = pContext->nInputFileType;

    if(nFileType == DISIGON_FILETYPE_AUTO)
        nFileType = get_file_type(pContext->szInputFile);

    LOG_DBG((0, "disigon_verify_verify", "Context: %p, FileType: %d", ctx, nFileType));

    strcpy(pVerifyResult->szInputFile, pContext->szInputFile);

    pVerifyResult->bVerifyCRL = pContext->bVerifyCRL;

    int nPos;

    long nRes = 0;
    switch(nFileType)
    {
    case DISIGON_FILETYPE_P7M:
        pVerifyResult->nResultType = DISIGON_FILETYPE_P7M;

        strcpy(pVerifyResult->szPlainTextFile, pContext->szInputFile);
        nPos = strlen(pContext->szInputFile) - 4; // toglie l'ultima estensione
        pVerifyResult->szPlainTextFile[nPos] = 0;

        nRes = verify_p7m(pContext, &pVerifyResult->verifyInfo);
        break;

    case DISIGON_FILETYPE_M7M:
        pVerifyResult->nResultType = DISIGON_FILETYPE_M7M;

        strcpy(pVerifyResult->szPlainTextFile, pContext->szInputFile);
        nPos = strlen(pContext->szInputFile) - 4; // toglie l'ultima estensione
        pVerifyResult->szPlainTextFile[nPos] = 0;

        nRes = verify_m7m(pContext, &pVerifyResult->verifyInfo);
        break;

    case DISIGON_FILETYPE_PDF:
        pVerifyResult->nResultType = DISIGON_FILETYPE_PDF;

        pVerifyResult->szPlainTextFile[0] = 0;

        nRes = verify_pdf(pContext, &pVerifyResult->verifyInfo);
        break;

    case DISIGON_FILETYPE_TSD:
        pVerifyResult->nResultType = DISIGON_FILETYPE_TSD;

        strcpy(pVerifyResult->szPlainTextFile, pContext->szInputFile);
        nPos = strlen(pContext->szInputFile) - 4; // toglie l'ultima estensione
        pVerifyResult->szPlainTextFile[nPos] = 0;

        nRes = verify_tsd(pContext, &pVerifyResult->verifyInfo);
        break;

    case DISIGON_FILETYPE_TSR:
        pVerifyResult->nResultType = DISIGON_FILETYPE_TSR;

        pVerifyResult->szPlainTextFile[0] = 0;

        nRes = verify_tsr(pContext, &pVerifyResult->verifyInfo);
        break;

    case DISIGON_FILETYPE_TST:
        pVerifyResult->nResultType = DISIGON_FILETYPE_TST;

        pVerifyResult->szPlainTextFile[0] = 0;

        nRes = verify_tst(pContext, &pVerifyResult->verifyInfo);
        break;

    case DISIGON_FILETYPE_XML:
        pVerifyResult->nResultType = DISIGON_FILETYPE_XML;

        pVerifyResult->szPlainTextFile[0] = 0;

        nRes = verify_xml(pContext, &pVerifyResult->verifyInfo);
        break;
        
    default:
        LOG_ERR((0, "<-- disigon_verify_verify", "Context: %p, Error: %x", pContext, DISIGON_ERROR_INVALID_FILE));
        nRes = DISIGON_ERROR_INVALID_FILE;
        break;
    }

    pVerifyResult->nErrorCode = nRes;


    LOG_MSG((0, "<-- disigon_verify_verify", "Context: %px", pContext));

    return nRes;

    __CATCH
}

long disigon_verify_cleanup(DISIGON_CTX ctx)
{
    LOG_MSG((0, "--> disigon_verify_cleanup", "Context: %p", ctx));

    __TRY

    DISIGON_VERIFY_CONTEXT* pContext = (DISIGON_VERIFY_CONTEXT*)ctx;

    SAFEDELETE(pContext);
    
    LOG_MSG((0, "<-- disigon_verify_cleanup", "Context: %p", ctx));

    return 0;

    __CATCH
}

long disigon_verify_cleanup_result(VERIFY_RESULT* pVerifyResult)
{
    LOG_MSG((0, "--> disigon_verify_cleanup_result", "VerifyResult: %p", pVerifyResult));

    __TRY

    if(!pVerifyResult)
        return 0;
    
    if(!pVerifyResult->verifyInfo.pSignerInfos)
        return 0;
    
    switch(pVerifyResult->nResultType)
    {
    case DISIGON_FILETYPE_P7M:
    case DISIGON_FILETYPE_PDF:
    case DISIGON_FILETYPE_XML:

        for(int i = 0; i < pVerifyResult->verifyInfo.pSignerInfos->nCount; i++)
        {
            if(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i].pTimeStamp)
            {
                if(((TS_INFO*)pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i].pTimeStamp)->signerInfo.pRevocationInfo)
                    SAFEDELETE(((TS_INFO*)pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i].pTimeStamp)->signerInfo.pRevocationInfo);

                SAFEDELETE(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i].pTimeStamp);
            }

            if(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i].pRevocationInfo)
                SAFEDELETE(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i].pRevocationInfo);

            //SAFEDELETE(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo[i]);
        }

        //SAFEDELETE(*(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo));
//        SAFEDELETE(pVerifyResult->verifyInfo.pSignerInfos->pSignerInfo);
        SAFEDELETE(pVerifyResult->verifyInfo.pSignerInfos);
        break;
    }

    LOG_MSG((0, "<-- disigon_verify_cleanup_result", "VerifyResult: %p", pVerifyResult));
    return 0;

    __CATCH
}


long verify_p7m(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_p7m", "Context: %p", pContext));

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- verify_p7m", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);

    try
    {
        CSignedDocument sd(data.getContent(), data.getLength());

        if(sd.isDetached())
        {
            if(pContext->szInputPlainTextFile[0] != '\0')
            {
                data.removeAll();
                f = fopen(pContext->szInputPlainTextFile, "rb");
                if(!f)
                {
                    LOG_ERR((0, "<-- verify_p7m", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputPlainTextFile));
                    return DISIGON_ERROR_FILE_NOT_FOUND;
                }

                while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
                {
                    data.append(buffer, nRead);
                }

                fclose(f);

                sd.setContent(data);
            }
            else
            {
                LOG_ERR((0, "<-- verify_p7m", "Context: %p, Error: DISIGON_ERROR_DETACHED_PKCS7, file: %s", pContext, pContext->szInputFile));
                return DISIGON_ERROR_DETACHED_PKCS7;
            }
        }

        long ret = verify_signed_document(pContext, sd, pVerifyInfo);
        
        if(ret != 0)
            return ret;
        
        #ifdef WIN32
        if(StrStrIA(pContext->szInputFile, ".pdf."))
        #else
        if(strcasestr(pContext->szInputFile, ".pdf."))
        #endif
        {
            // pdf inside a P7M, check signature in the pdf
            
            UUCByteArray content;
            sd.getContent(content);
            
            VERIFY_INFO verifyInfo;
            
            ret = verify_pdf(pContext, content, &verifyInfo);
            if(ret != 0)
                return ret;
            
            int p7mSignatures = pVerifyInfo->pSignerInfos->nCount;
            int pdfSignatures = verifyInfo.pSignerInfos->nCount;
            
            SIGNER_INFOS* p7mSignerInfos = pVerifyInfo->pSignerInfos;
            SIGNER_INFOS* pdfSignerInfos = verifyInfo.pSignerInfos;
            
            TS_INFO* p7mTSInfo = pVerifyInfo->pTSInfo;
            //TS_INFO* pdfTSInfo = verifyInfo.pTSInfo;
            
            pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
            pVerifyInfo->pSignerInfos->nCount = p7mSignatures + pdfSignatures;
            pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[p7mSignatures + pdfSignatures];

            int i = 0;
            for(i = 0; i < p7mSignatures; i++)
            {
                pVerifyInfo->pSignerInfos->pSignerInfo[i] = p7mSignerInfos->pSignerInfo[i];
            }

            for(int j = 0; j < pdfSignatures; j++)
            {
                pVerifyInfo->pSignerInfos->pSignerInfo[i + j] = pdfSignerInfos->pSignerInfo[j];
            }

            pVerifyInfo->pTSInfo = p7mTSInfo;
            
            SAFEDELETE(p7mSignerInfos)
            SAFEDELETE(pdfSignerInfos)
                        
        }
        
        return 0;
    }
    catch(...)
    {
        return DISIGON_ERROR_INVALID_FILE;
    }
}

long disigon_get_file_from_p7m(DISIGON_CTX ctx) {


	DISIGON_VERIFY_CONTEXT* pContext = (DISIGON_VERIFY_CONTEXT*)ctx;

	LOG_MSG((0, "--> get_file_from_p7m", "Context: %p", pContext));



    int nFileType = pContext->nInputFileType;

    if(nFileType == DISIGON_FILETYPE_AUTO)
        nFileType = get_file_type(pContext->szInputFile);

    if(nFileType != DISIGON_FILETYPE_P7M)
        return DISIGON_ERROR_INVALID_FILE;

	UUCByteArray data;
	BYTE buffer[BUFFERSIZE];
	int nRead = 0;

	FILE* f = fopen(pContext->szInputFile, "rb");
	if (!f)
	{
		LOG_ERR((0, "<-- get_file_from_p7m", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
		return DISIGON_ERROR_FILE_NOT_FOUND;
	}

	while (((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
	{
		data.append(buffer, nRead);
	}
    

	fclose(f);

	try
	{
		CSignedDocument sd(data.getContent(), data.getLength());

        UUCByteArray content;
        sd.getContent(content);

        FILE* f = fopen(pContext->szOutputFile, "w+b");
        if (!f)
        {
            LOG_ERR((0, "<-- get_file_from_p7m - output file", "Context: %p, Error: QDIGITSIGN_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szOutputFile));
            return DISIGON_ERROR_FILE_NOT_FOUND;
        }

        fwrite(content.getContent(), 1, content.getLength(), f);

        fclose(f);

        return 0;
	}
	catch (...)
	{
		return DISIGON_ERROR_INVALID_FILE;
	}
}

long verify_xml(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_xml", "Context: %p", pContext));

    UUCByteArray data;
    int nRead = 0;

    CXAdESVerifier verifier;

    int signatureCount = verifier.Load(pContext->szInputFile);

    pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
    pVerifyInfo->pSignerInfos->nCount = signatureCount;
    

    //pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO*;
    pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[signatureCount];


    for(int i = 0; i < signatureCount; i++)
    {
        CCertificate* pCert = verifier.GetCertificate(i);
            
        //SIGNER_INFO* pSI = new SIGNER_INFO;
        SIGNER_INFO* pSI = &(pVerifyInfo->pSignerInfos->pSignerInfo[i]);

        pSI->pCounterSignatures = NULL;
        pSI->nCounterSignatureCount = 0;
        pSI->szSigningTime[0] = NULL;
        pSI->pRevocationInfo = NULL;
        pSI->pTimeStamp = NULL;
        pSI->b2011Error = false;
    
        CASN1ObjectIdentifier digestOID = verifier.GetDigestAlgorithm(i);
        UUCByteArray oid;
        digestOID.ToOidString(oid);
        strcpy(pSI->szDigestAlgorithm, (char*)oid.getContent());

        if(pContext->bVerifyCRL)
            pSI->pRevocationInfo = new REVOCATION_INFO;

        pSI->bitmask = verifier.verifySignature(i, NULL, pSI->pRevocationInfo);

        string giveName = pCert->getSubject().getField(OID_GIVEN_NAME);
        string surname = pCert->getSubject().getField(OID_SURNAME);
        string commonName = pCert->getSubject().getField(OID_COMMON_NAME);
                
        strcpy(pSI->szCN, commonName.c_str());
        strcpy(pSI->szGIVENNAME, giveName.c_str());
        strcpy(pSI->szSURNAME, surname.c_str());
        
        UUCByteArray subject;
        pCert->getSubject().getNameAsString(subject);
        
        strcpy(pSI->szDN, (char*)subject.getContent());
        strcpy(pSI->szSN, ((UUCByteArray*)pCert->getSerialNumber().getValue())->toHexString());
        
        CASN1Sequence certExtensions(pCert->getExtensions());
        CASN1Sequence extensions = certExtensions.elementAt(0);
        int count = extensions.size();
        pSI->nExtensionsCount = count;
        pSI->pszExtensions = new char*[count];
        for(int j = 0; j < count; j++)
        {
            CASN1Sequence extension = extensions.elementAt(j);
            CASN1ObjectIdentifier extoid = extension.elementAt(0);
            CASN1OctetString value(extension.elementAt(1));
            UUCByteArray oidName;
            extoid.ToOidString(oidName);
            const char* szoid = g_mapOIDProps.getProperty((char*)oidName.getContent(), (char*)oidName.getContent());
            const char* hexval = ((UUCByteArray*)value.getValue())->toHexString();
            char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
            sprintf(szAux, "%s:%s", szoid, hexval);
            pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
            strcpy(pSI->pszExtensions[j], szAux);
            delete szAux;
        }

        UUCByteArray issuer;
        pCert->getIssuer().getNameAsString(issuer);
        strcpy(pSI->szCADN, (char*)issuer.getContent());

        pCert->getExpiration().getUTCTime(pSI->szExpiration);
        pCert->getFrom().getUTCTime(pSI->szValidFrom);

        UUCByteArray certificate;
        pCert->toByteArray(certificate);

        pSI->nCertLen = certificate.getLength();
        pSI->pCertificate = new BYTE[pSI->nCertLen];
        memcpy(pSI->pCertificate, certificate.getContent(), pSI->nCertLen);



/*
        if(si.hasTimeStampToken())
        {
            CTimeStampToken tst = si.getTimeStampToken();

            TS_INFO* pTSInfo = new TS_INFO;

            CCertificate tsacert(tst.getCertificates().elementAt(0));

            strcpy(pTSInfo->szCN, tsacert.getSubject().getField(OID_NAME).c_str());
            strcpy(pTSInfo->szCACN, tsacert.getIssuer().getField(OID_NAME).c_str());

            CTSTInfo tstInfo(tst.getTSTInfo());

            strcpy(pSI->szSN, ((UUCByteArray*)tstInfo.getSerialNumber().getValue())->toHexString());

            tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

            tsacert.getExpiration().getUTCTime(pTSInfo->szExpiration);
            
            pTSInfo->bitmask = tst.verify(pContext->bVerifyCRL);

            pSI->pTimeStamp = pTSInfo;
        }
        else
        {
            pSI->pTimeStamp = NULL;
        }
*/
        //pVerifyInfo->pSignerInfos->pSignerInfo[i] = pSI;

    }

    LOG_MSG((0, "<-- verify_xml", "Context: %p", pContext));

    return 0;
}


long verify_m7m(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_m7m", "Context: %p", pContext));

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- verify_m7m", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);

    M7MParser m7mParser;

    int nRes = m7mParser.Load((char*)data.getContent(), data.getLength());
    if(nRes)
        return nRes;

    UUCByteArray p7mData;
    nRes = m7mParser.GetP7M(p7mData);
    if(nRes)
        return nRes;

    UUCByteArray tsrData;
    nRes = m7mParser.GetTSR(tsrData);
    if(nRes)
        return nRes;

    CSignedDocument sd(p7mData.getContent(), p7mData.getLength());
/*
    if(pContext->szOutputFile[0] != 0)
    {
        UUCByteArray content;
        sd.getContent(content);

        f = fopen(pContext->szOutputFile, "w+b");
        if(!f)
        {
            LOG_ERR((0, "<-- verify_m7m", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szOutputFile));
            return DISIGON_ERROR_FILE_NOT_FOUND;
        }

        fwrite(content.getContent(), 1, content.getLength(), f);

        fclose(f);
    }
*/
    if(sd.isDetached())
    {
        if(pContext->szInputPlainTextFile[0] != '\0')
        {
            UUCByteArray fileData;
            f = fopen(pContext->szInputPlainTextFile, "rb");
            if(!f)
            {
                LOG_ERR((0, "<-- verify_m7m", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputPlainTextFile));
                return DISIGON_ERROR_FILE_NOT_FOUND;
            }

            while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
            {
                fileData.append(buffer, nRead);
            }

            fclose(f);

            sd.setContent(fileData);
        }
        else
        {
            LOG_ERR((0, "<-- verify_m7m", "Context: %p, Error: DISIGON_ERROR_DETACHED_PKCS7, file: %s", pContext, pContext->szInputFile));
            return DISIGON_ERROR_DETACHED_PKCS7;
        }
    }

    nRes = verify_signed_document(pContext, sd, pVerifyInfo);
    if(nRes)
    {
        LOG_ERR((0, "<-- verify_m7m", "Context: %p, Error: %x", pContext, nRes));
        return nRes;
    }

    //pVerifyInfo->pSignerInfos->pSignerInfo[0]->pTimeStamp = new TS_INFO;
    pVerifyInfo->pTSInfo = new TS_INFO;

    UUCBufferedReader reader(tsrData);
    CTimeStampResponse tsr(reader);
    CTimeStampToken tst(tsr.getTimeStampToken());

    return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);
}

int getEmbeddedSignatureCount(CSignedDocument& sd)
{
    LOG_DBG((0, "--> getEmbeddedSignatureCount", ""));

    UUCByteArray content;
    sd.getContent(content);

    try
    {
        //LOG_DBG((0, "getEmbeddedSignatureCount", "Create SignedDocument"));

        const BYTE* bt = content.getContent();
        int len = content.getLength();

        //LOG_DBG((0, "getEmbeddedSignatureCount", "Create SignedDocument: %d", len));

        CSignedDocument sd1(bt, len);

        //LOG_DBG((0, "getEmbeddedSignatureCount", "Create SignedDocument OK"));

        int n = sd.getSignerCount() + getEmbeddedSignatureCount(sd1);
    
        LOG_DBG((0, "getEmbeddedSignatureCount", "Signature count: %d", n));

        return n;
    }
    catch(...)
    {
        LOG_DBG((0, "getEmbeddedSignatureCount", "Not embedded signature"));

        int n = sd.getSignerCount();

        LOG_DBG((0, "getEmbeddedSignatureCount", "Signature Count: %d", n));

        return n;
    }
}


SIGNER_INFO* verify_countersignature(DISIGON_VERIFY_CONTEXT* pContext, CSignerInfo& si, CASN1SetOf& certificates, SIGNER_INFO* pSignerInfo, VERIFY_INFO* pVerifyInfo)
{
    LOG_DBG((0, "--> verify_countersignature", ""));

    int counterSignatureCount = si.getCountersignatureCount();
    if(counterSignatureCount > 0)
    {
        CASN1SetOf counterSignatures = si.getCountersignatures();

        
        pSignerInfo->pCounterSignatures = new SIGNER_INFO[counterSignatureCount];
        pSignerInfo->nCounterSignatureCount = counterSignatureCount;

        for(int i = 0; i < counterSignatureCount; i++)
        {
            CSignerInfo counterSignature = counterSignatures.elementAt(i);
            
            CCertificate cert = CSignerInfo::getSignatureCertificate(counterSignature, certificates);

            //SIGNER_INFO* pSI = new SIGNER_INFO;

            SIGNER_INFO* pSI = &(((SIGNER_INFO*)pSignerInfo->pCounterSignatures)[i]);
            pSI->pTimeStamp = NULL;
            pSI->pCounterSignatures = NULL;
            pSI->nCounterSignatureCount = 0;
            pSI->pRevocationInfo = NULL;
            if(pContext->bVerifyCRL)
                pSI->pRevocationInfo = new REVOCATION_INFO;

            //LOG_DBG((0, "verify_signed_document 2", "verify : %d", pContext->bVerifyCRL));

            pSI->bitmask = si.verifyCountersignature(i, certificates, NULL, pSI->pRevocationInfo);

            LOG_DBG((0, "verify_countersignature", "verify result: %x", pSI->bitmask));

            UUCByteArray issuer;
            cert.getIssuer().getNameAsString(issuer);

            //LOG_DBG((0, "verify_signed_document 2", "issuer: %s", issuer.getContent()));

            UUCByteArray subject;
            cert.getSubject().getNameAsString(subject);

            //LOG_DBG((0, "verify_signed_document 2", "subject: %s", subject.getContent()));

            string giveName = cert.getSubject().getField(OID_GIVEN_NAME);
            string surname = cert.getSubject().getField(OID_SURNAME);
            string commonName = cert.getSubject().getField(OID_COMMON_NAME);
                    
            strcpy(pSI->szCN, commonName.c_str());
            strcpy(pSI->szGIVENNAME, giveName.c_str());
            strcpy(pSI->szSURNAME, surname.c_str());
            
            strcpy(pSI->szDN, (char*)subject.getContent());

            //LOG_DBG((0, "verify_signed_document 2", "CN: %s", pSI->szCN));

            strcpy(pSI->szSN, ((UUCByteArray*)cert.getSerialNumber().getValue())->toHexString());
        
            //LOG_DBG((0, "verify_signed_document 2", "CN: %s, SN: %s", pSI->szCN, pSI->szSN));

            strcpy(pSI->szCADN, (char*)issuer.getContent());

            //LOG_DBG((0, "verify_signed_document 2", "CACN: %s", pSI->szCACN));

            CASN1ObjectIdentifier digestOID = si.getDigestAlgorithn().elementAt(0);
            UUCByteArray oid;
            digestOID.ToOidString(oid);
            strcpy(pSI->szDigestAlgorithm, (char*)oid.getContent());

            //LOG_DBG((0, "verify_signed_document 2", "Algo: %s", pSI->szDigestAlgorithm));

            CASN1Sequence certExtensions(cert.getExtensions());
            CASN1Sequence extensions = certExtensions.elementAt(0);
            int count = extensions.size();
            pSI->nExtensionsCount = count;
            pSI->pszExtensions = new char*[count];
            for(int j = 0; j < count; j++)
            {
                CASN1Sequence extension = extensions.elementAt(j);
                CASN1ObjectIdentifier extoid = extension.elementAt(0);
                CASN1OctetString value(extension.elementAt(1));
                
                UUCByteArray oidName;
                extoid.ToOidString(oidName);
                const char* szoid = g_mapOIDProps.getProperty((char*)oidName.getContent(), (char*)oidName.getContent());
                const char* hexval = ((UUCByteArray*)value.getValue())->toHexString();
                char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
                sprintf(szAux, "%s:%s", szoid, hexval);
                pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
                strcpy(pSI->pszExtensions[j], szAux);
                delete szAux;
            }

            //LOG_DBG((0, "verify_signed_document 2", "Estension OK"));

            cert.getExpiration().getUTCTime(pSI->szExpiration);
            cert.getFrom().getUTCTime(pSI->szValidFrom);

            UUCByteArray certificate;
            cert.toByteArray(certificate);

            pSI->nCertLen = certificate.getLength();
            pSI->pCertificate = new BYTE[pSI->nCertLen];
            memcpy(pSI->pCertificate, certificate.getContent(), pSI->nCertLen);

            strcpy(pSI->szSigningTime, "");

            try
            {
                CASN1UTCTime signingTime = si.getSigningTime();

                char szTime[MAX_LEN];
                signingTime.getUTCTime(szTime);
                strcpy(pSI->szSigningTime, szTime);

                pSI->b2011Error = (!(pSI->bitmask & VERIFIED_CERT_SHA256)) && (strncmp(szTime, "110630", 6) > 0);

            }
            catch(...)
            {
                strcpy(pSI->szSigningTime, "");
                pSI->b2011Error = false;
            }

    //        string certv2;
    //        certv2id.ToOidString(certv2);
    //        strcpy(pSI->szCertificateV2, certv2.c_str());
            strcpy(pSI->szCertificateV2, szSHA256OID); // default value

            if(si.hasTimeStampToken())
            {
                LOG_DBG((0, "verify_signed_document 2", "Has TimeStamp"));

                CTimeStampToken tst = si.getTimeStampToken();

                TS_INFO* pTSInfo = new TS_INFO;

                CCertificate tsacert(tst.getCertificates().elementAt(0));

                UUCByteArray subject;
                UUCByteArray issuer;
                
                tsacert.getSubject().getNameAsString(subject);
                tsacert.getIssuer().getNameAsString(issuer);

                strcpy(pTSInfo->signerInfo.szDN, (char*)subject.getContent());
                strcpy(pTSInfo->signerInfo.szCADN, (char*)issuer.getContent());

                CTSTInfo tstInfo(tst.getTSTInfo());
                
                strcpy(pTSInfo->signerInfo.szSN, ((UUCByteArray*)cert.getSerialNumber().getValue())->toHexString());
                strcpy(pTSInfo->szTimeStampSerial, ((UUCByteArray*)tstInfo.getSerialNumber().getValue())->toHexString());

                tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);
                
                tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
                tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);
                //pTSInfo->signerInfo.pCertificate = new  CCertificate(tsacert);

                UUCByteArray* certificate = (UUCByteArray*)tsacert.getValue();

                pTSInfo->signerInfo.nCertLen = certificate->getLength();
                pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
                memcpy(pTSInfo->signerInfo.pCertificate, certificate->getContent(), pTSInfo->signerInfo.nCertLen);


                pTSInfo->signerInfo.pRevocationInfo = NULL;
                if(pContext->bVerifyCRL)
                    pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;
            
                pTSInfo->signerInfo.bitmask = tst.verify(pTSInfo->signerInfo.pRevocationInfo);

                // MessageImprint
                CASN1Sequence messageImprint = tstInfo.getMessageImprint();
                
                // algo
                CAlgorithmIdentifier algoid(messageImprint.elementAt(0));
                CASN1ObjectIdentifier timeStampImprintAlgorithm(algoid.elementAt(0));

                UUCByteArray oid1;
                timeStampImprintAlgorithm.ToOidString(oid1);
                strcpy(pTSInfo->szTimeStampImprintAlgorithm, (char*)oid1.getContent());

                // imprint b64
                CASN1OctetString mimprint = messageImprint.elementAt(1);
                const UUCByteArray* val = mimprint.getValue();

                size_t encLen = base64_encoded_size(val->getLength());
                char* szEncoded = base64_encode((char*)val->getContent(), val->getLength());
            
                strcpy(pTSInfo->szTimeStampMessageImprint, szEncoded);

                free(szEncoded);

                // digest algo
                CASN1ObjectIdentifier digestOID(tstInfo.getDigestAlgorithn().elementAt(0));
                UUCByteArray oid;
                digestOID.ToOidString(oid);
                strcpy(pTSInfo->signerInfo.szDigestAlgorithm, (char*)oid.getContent());
    /*
                CASN1Sequence certExtensions(tsacert.getExtensions());
                CASN1Sequence extensions = certExtensions.elementAt(0);
                int count = extensions.size();
                pTSInfo->signerInfo.nExtensionsCount = count;
                pTSInfo->signerInfo.pszExtensions = new char*[count];
                for(int i = 0; i < count; i++)
                {
                    CASN1Sequence extension = extensions.elementAt(i);
                    CASN1ObjectIdentifier extoid = extension.elementAt(0);
                    CASN1OctetString value(extension.elementAt(1));
                    
                    UUCByteArray oidName;
                    extoid.ToOidString(oidName);
                    const char* szoid = g_mapOIDProps.getProperty((char*)oidName.getContent(), (char*)oidName.getContent());
                    const char* hexval = ((UUCByteArray*)value.getValue())->toHexString();
                    char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
                    sprintf(szAux, "%s:%s", szoid, hexval);
                    pSI->pszExtensions[i] = new char[strlen(szAux) + 1];
                    strcpy(pTSInfo->signerInfo.pszExtensions[i], szAux);
                    delete szAux;
                }
    */
                pSI->pTimeStamp = pTSInfo;
            }
            else
            {
                LOG_DBG((0, "verify_signed_document 2", "Doesn't Have TimeStamp"));

                pSI->pTimeStamp = NULL;
            }

            //pSignerInfo->pCounterSignatures[i] = pSI;

            if(counterSignature.getCountersignatureCount() > 0)
            {
                verify_countersignature(pContext, counterSignature, certificates, pSI, pVerifyInfo);
            }

            LOG_DBG((0, "verify_countersignature", "Set SI: %d", i));
        
        }
    }



    LOG_DBG((0, "--> verify_countersignature", ""));

    return 0;
}


long verify_signed_document(int index, DISIGON_VERIFY_CONTEXT* pContext, CSignedDocument& sd, VERIFY_INFO* pVerifyInfo)
{
    LOG_DBG((0, "--> verify_signed_document 2", "Index: %d", index));

    int sigCount = sd.getSignerCount();

    LOG_DBG((0, "verify_signed_document 2", "sigCount: %d", sigCount));
    
    for(int i = 0; i < sigCount; i++)
    {
        CCertificate cert = sd.getSignerCertificate(i);
        
        //LOG_DBG((0, "verify_signed_document 2", "Cert OK: %d", i));

        CSignerInfo si = sd.getSignerInfo(i);
        
        //LOG_DBG((0, "verify_signed_document 2", "SignerInfo OK: %d", i));

        //SIGNER_INFO* pSI = new SIGNER_INFO;
        SIGNER_INFO* pSI = &(pVerifyInfo->pSignerInfos->pSignerInfo[index]);// = pSI;

        pSI->pTimeStamp = NULL;
        pSI->pCounterSignatures = NULL;
        pSI->nCounterSignatureCount = 0;
        pSI->pRevocationInfo = NULL;
        if(pContext->bVerifyCRL)
            pSI->pRevocationInfo = new REVOCATION_INFO;

        //LOG_DBG((0, "verify_signed_document 2", "verify : %d", pContext->bVerifyCRL));

        pSI->bitmask = sd.verify(i, pSI->pRevocationInfo);//pContext->bVerifyCRL);

        LOG_DBG((0, "verify_signed_document 2", "verify result: %x", pSI->bitmask));

        UUCByteArray issuer;
        cert.getIssuer().getNameAsString(issuer);

        //LOG_DBG((0, "verify_signed_document 2", "issuer: %s", issuer.getContent()));

        UUCByteArray subject;
        cert.getSubject().getNameAsString(subject);

        string giveName = cert.getSubject().getField(OID_GIVEN_NAME);
        string surname = cert.getSubject().getField(OID_SURNAME);
        string commonName = cert.getSubject().getField(OID_COMMON_NAME);
                
        strcpy(pSI->szCN, commonName.c_str());
        strcpy(pSI->szGIVENNAME, giveName.c_str());
        strcpy(pSI->szSURNAME, surname.c_str());
        
        strcpy(pSI->szDN, (char*)subject.getContent());

        //LOG_DBG((0, "verify_signed_document 2", "CN: %s", pSI->szCN));

        strcpy(pSI->szSN, ((UUCByteArray*)cert.getSerialNumber().getValue())->toHexString());
        
        //LOG_DBG((0, "verify_signed_document 2", "CN: %s, SN: %s", pSI->szCN, pSI->szSN));

        strcpy(pSI->szCADN, (char*)issuer.getContent());

        //LOG_DBG((0, "verify_signed_document 2", "CACN: %s", pSI->szCACN));


        CASN1ObjectIdentifier digestOID = si.getDigestAlgorithn().elementAt(0);
        UUCByteArray oid;
        digestOID.ToOidString(oid);
        strcpy(pSI->szDigestAlgorithm, (char*)oid.getContent());

        //LOG_DBG((0, "verify_signed_document 2", "Algo: %s", pSI->szDigestAlgorithm));

        CASN1Sequence certExtensions(cert.getExtensions());
        CASN1Sequence extensions = certExtensions.elementAt(0);
        int count = extensions.size();
        pSI->nExtensionsCount = count;
        pSI->pszExtensions = new char*[count];
        for(int j = 0; j < count; j++)
        {
            CASN1Sequence extension = extensions.elementAt(j);
            CASN1ObjectIdentifier extoid = extension.elementAt(0);
            CASN1OctetString value(extension.elementAt(1));
            
            UUCByteArray oidName;
            extoid.ToOidString(oidName);
            const char* szoid = g_mapOIDProps.getProperty((char*)oidName.getContent(), (char*)oidName.getContent());
            const char* hexval = ((UUCByteArray*)value.getValue())->toHexString();
            char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
            sprintf(szAux, "%s:%s", szoid, hexval);
            pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
            strcpy(pSI->pszExtensions[j], szAux);
            delete szAux;
        }

        //LOG_DBG((0, "verify_signed_document 2", "Estension OK"));

        cert.getExpiration().getUTCTime(pSI->szExpiration);
        cert.getFrom().getUTCTime(pSI->szValidFrom);

        UUCByteArray certificate;
        cert.toByteArray(certificate);

        pSI->nCertLen = certificate.getLength();
        pSI->pCertificate = new BYTE[pSI->nCertLen];
        memcpy(pSI->pCertificate, certificate.getContent(), pSI->nCertLen);
        // Se hai percorsi CA nel contesto, mettili qui (altrimenti lascia nullptr)
        
        const char* ca_file = nullptr;   // es: pContext->szCAFile;
        const char* ca_path = nullptr;   // es: pContext->szCAPath;
        const char* extra_pem = nullptr; // es: pContext->pExtraCABundlePEM;

        // 1) Tempo di verifica: usa la signingTime se presente, altrimenti "adesso"
        const char* verify_time = (pSI->szSigningTime[0] ? pSI->szSigningTime : nullptr);

        int chain_ok = verify_chain_from_der_at_time(
            certificate.getContent(),
            certificate.getLength(),
            ca_file, ca_path, extra_pem,
            verify_time
        );

        if (chain_ok) {
            pSI->bitmask |= VERIFIED_CERT_CHAIN;
        } else {
            pSI->bitmask &= ~VERIFIED_CERT_CHAIN;
            LOG_ERR((0, "verify_pdf", "Certificate chain: FAIL (signer %d)", i));
        }

        // 2) VALIDITY esplicita (indipendente dal pdfVerifier)
        //    Se verify_time==nullptr, confrontiamo con l'ora corrente.
        //    Usiamo OpenSSL per confrontare notBefore/notAfter con un time_t scelto.
        {
            // Costruisci X509 per leggere le date
            const unsigned char* p = certificate.getContent();
            X509* leaf = d2i_X509(nullptr, &p, certificate.getLength());
            bool timeOK = false;
            if (leaf) {
                // scegli il time_t di verifica
                time_t tt = time(nullptr);
                if (verify_time && verify_time[0]) {
                    // parser “robusto” stile ASN.1 (YYMMDDhhmmssZ o YYYYMMDDhhmmssZ)
                    time_t parsed{};
                    if (parse_asn1_like_utc(verify_time, parsed)) tt = parsed;
                }

                // Confronta notBefore/notAfter con tt
                const ASN1_TIME* nb = X509_get0_notBefore(leaf);
                const ASN1_TIME* na = X509_get0_notAfter(leaf);
                // OpenSSL helper: <0 se nb > tt (non ancora valido), >0 se na < tt (scaduto)
                int tooEarly = X509_cmp_time(nb, &tt); // >0 => nb > tt (non valido ancora)
                int tooLate  = X509_cmp_time(na, &tt); // <0 => na < tt (scaduto)
                timeOK = (tooEarly <= 0) && (tooLate >= 0);
                X509_free(leaf);
            }
            if (timeOK)  pSI->bitmask |=  VERIFIED_CERT_VALIDITY;
            else         pSI->bitmask &= ~VERIFIED_CERT_VALIDITY;
        }
        strcpy(pSI->szSigningTime, "");

        try
        {
            CASN1UTCTime signingTime = si.getSigningTime();

            char szTime[MAX_LEN];
            signingTime.getUTCTime(szTime);
            strcpy(pSI->szSigningTime, szTime);

            pSI->b2011Error = (!(pSI->bitmask & VERIFIED_CERT_SHA256)) && (strncmp(szTime, "110630", 6) > 0);

        }
        catch(...)
        {
            strcpy(pSI->szSigningTime, "");
            pSI->b2011Error = false;
        }

//        string certv2;
//        certv2id.ToOidString(certv2);
//        strcpy(pSI->szCertificateV2, certv2.c_str());
        strcpy(pSI->szCertificateV2, szSHA256OID); // default value

    
        int counterSignatureCount = si.getCountersignatureCount();
        if(counterSignatureCount > 0)
        {
            CASN1SetOf certificates = sd.getCertificates();
            verify_countersignature(pContext, si, certificates, pSI, pVerifyInfo);
        }
    
        if(si.hasTimeStampToken())
        {
            LOG_DBG((0, "verify_signed_document 2", "Has TimeStamp"));

            CTimeStampToken tst = si.getTimeStampToken();

            TS_INFO* pTSInfo = new TS_INFO;

            CCertificate tsacert(tst.getCertificates().elementAt(0));

            UUCByteArray subject;
            UUCByteArray issuer;
            
            tsacert.getSubject().getNameAsString(subject);
            tsacert.getIssuer().getNameAsString(issuer);

            strcpy(pTSInfo->signerInfo.szDN, (char*)subject.getContent());
            strcpy(pTSInfo->signerInfo.szCADN, (char*)issuer.getContent());

            CTSTInfo tstInfo(tst.getTSTInfo());
            
            strcpy(pTSInfo->signerInfo.szSN, ((UUCByteArray*)cert.getSerialNumber().getValue())->toHexString());
            strcpy(pTSInfo->szTimeStampSerial, ((UUCByteArray*)tstInfo.getSerialNumber().getValue())->toHexString());

            tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);
            
            tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
            tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);
            
            UUCByteArray certificate;
            tsacert.toByteArray(certificate);

            pTSInfo->signerInfo.nCertLen = certificate.getLength();
            pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
            memcpy(pTSInfo->signerInfo.pCertificate, certificate.getContent(), pTSInfo->signerInfo.nCertLen);

            pTSInfo->signerInfo.pRevocationInfo = NULL;
            if(pContext->bVerifyCRL)
                pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;
        
            pTSInfo->signerInfo.bitmask = tst.verify(pTSInfo->signerInfo.pRevocationInfo);

            // MessageImprint
            CASN1Sequence messageImprint = tstInfo.getMessageImprint();
            
            // algo
            CAlgorithmIdentifier algoid(messageImprint.elementAt(0));
            CASN1ObjectIdentifier timeStampImprintAlgorithm(algoid.elementAt(0));

            UUCByteArray oid1;
            timeStampImprintAlgorithm.ToOidString(oid1);
            strcpy(pTSInfo->szTimeStampImprintAlgorithm, (char*)oid1.getContent());

            // imprint b64
            CASN1OctetString mimprint = messageImprint.elementAt(1);
            const UUCByteArray* val = mimprint.getValue();

            size_t encLen = base64_encoded_size(val->getLength());
            char* szEncoded = base64_encode((char*)val->getContent(), val->getLength());
        
            strcpy(pTSInfo->szTimeStampMessageImprint, szEncoded);

            free(szEncoded);

            // digest algo
            CASN1ObjectIdentifier digestOID(tstInfo.getDigestAlgorithn().elementAt(0));
            UUCByteArray oid;
            digestOID.ToOidString(oid);
            strcpy(pTSInfo->signerInfo.szDigestAlgorithm, (char*)oid.getContent());
/*
            CASN1Sequence certExtensions(tsacert.getExtensions());
            CASN1Sequence extensions = certExtensions.elementAt(0);
            int count = extensions.size();
            pTSInfo->signerInfo.nExtensionsCount = count;
            pTSInfo->signerInfo.pszExtensions = new char*[count];
            for(int i = 0; i < count; i++)
            {
                CASN1Sequence extension = extensions.elementAt(i);
                CASN1ObjectIdentifier extoid = extension.elementAt(0);
                CASN1OctetString value(extension.elementAt(1));
                
                UUCByteArray oidName;
                extoid.ToOidString(oidName);
                const char* szoid = g_mapOIDProps.getProperty((char*)oidName.getContent(), (char*)oidName.getContent());
                const char* hexval = ((UUCByteArray*)value.getValue())->toHexString();
                char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
                sprintf(szAux, "%s:%s", szoid, hexval);
                pSI->pszExtensions[i] = new char[strlen(szAux) + 1];
                strcpy(pTSInfo->signerInfo.pszExtensions[i], szAux);
                delete szAux;
            }
*/
            pSI->pTimeStamp = pTSInfo;
        }
        else
        {
            LOG_DBG((0, "verify_signed_document 2", "Doesn't Have TimeStamp"));

            pSI->pTimeStamp = NULL;
        }

        //pVerifyInfo->pSignerInfos->pSignerInfo[index] = pSI;

        //LOG_DBG((0, "verify_signed_document 2", "Set SI: %d", index));

        index++;
    }

    //LOG_DBG((0, "verify_signed_document 2", "exiting"));

    try
    {
        UUCByteArray content;
        sd.getContent(content);
        CSignedDocument sd1(content.getContent(), content.getLength());
        LOG_DBG((0, "<-- verify_signed_document 2", ""));
        return verify_signed_document(index, pContext, sd1, pVerifyInfo);
    }
    catch(...)
    {
        LOG_DBG((0, "verify_signed_document 2", "no embedded signature"));
    }

    LOG_MSG((0, "<-- verify_signed_document", "Context: %p", pContext));

    return 0;
}

long verify_signed_document(DISIGON_VERIFY_CONTEXT* pContext, CSignedDocument& sd, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_signed_document", "Context: %p", pContext));

    int signatureCount = getEmbeddedSignatureCount(sd);

    LOG_MSG((0, "verify_signed_document", "Signature Count: %d", signatureCount));

    pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
    pVerifyInfo->pSignerInfos->nCount = signatureCount;// = sd.getSignerCount();

    //LOG_DBG((0, "verify_signed_document", "Alloc 1 OK: %d", signatureCount));

    //pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO*;
    pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[signatureCount];

    //LOG_DBG((0, "verify_signed_document", "Alloc 2 OK: %d", signatureCount));

    return verify_signed_document(0, pContext, sd, pVerifyInfo);
}


long sign_xml(DISIGON_SIGN_CONTEXT* pContext, UUCByteArray& data)
{
    LOG_MSG((0, "--> sign_xml", "Context: %p", pContext));

    CXAdESGenerator xadesGenerator(pContext->pSignatureGenerator);

    xadesGenerator.SetData(data);
    xadesGenerator.SetXAdES(pContext->pSignatureGenerator->GetCAdES());
    xadesGenerator.SetFileName(pContext->szInputFile);

    
    UUCByteArray xadesData;
    long nRes = xadesGenerator.Generate(xadesData, pContext->bDetached, pContext->bVerifyCert);
    if(nRes)
    {
        return nRes;
    }

    if(pContext->szOutputFile[0] == 0)
    {
        if (pContext->bDetached)
            sprintf(pContext->szOutputFile, "signed_%s.xml", pContext->szInputFile);
        else
            sprintf(pContext->szOutputFile, "%s.xml",  pContext->szInputFile);
    }

    FILE* f = fopen(pContext->szOutputFile, "w+b");
    if(!f)
    {
        LOG_ERR((0, "<-- sign_xml", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szOutputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    fwrite(xadesData.getContent(), 1, xadesData.getLength(), f);

    fclose(f);

    LOG_MSG((0, "<-- sign_xml", "Context: %p, RetVal: %x", pContext, nRes));

    return nRes;
}

long sign_pdf(DISIGON_SIGN_CONTEXT* pContext, UUCByteArray& data)
{
    LOG_MSG((0, "--> sign_pdf", "Context: %p", pContext));

    PdfSignatureGenerator sigGen;

    int nSigCount = sigGen.Load((char*)data.getContent(), data.getLength());

    LOG_DBG((0, "sign_pdf", "Context: %p, SigCount %d", pContext, nSigCount));

    string sigName = "Signature";
    sigName += ('1' + nSigCount);

    LOG_DBG((0, "sign_pdf", "Context: %p, InitSignature %d, %f, %f, %f, %f, %s, %s, %s, %s, %s, %s", pContext, pContext->nPdfPage, pContext->fPdfLeft, pContext->fPdfBottom, pContext->fPdfWidth, pContext->fPdfHeight, pContext->szPdfReason, pContext->szPdfName, pContext->szPdfLocation, sigName.c_str(), pContext->szPdfSubfilter, pContext->szPdfImagePath));


    if(pContext->szPdfImagePath[0] != 0 || pContext->szPdfDescription[0] != 0 || (pContext->fPdfLeft + pContext->fPdfBottom + pContext->fPdfWidth + pContext->fPdfHeight) != 0)
    {
        if(!pContext->szPdfReason[0])
        {
            CCertificate* pCertificate;
            long r = pContext->pSignatureGenerator->GetCertificate(&pCertificate);
            if(r == 0)
            {
                string giveName = pCertificate->getSubject().getField(OID_GIVEN_NAME);
                string surname = pCertificate->getSubject().getField(OID_SURNAME);
                
                sprintf(pContext->szPdfReason, "%s %s", giveName.c_str(), surname.c_str());
                
                time_t rawtime;
                struct tm * timeinfo;
                char buffer[80];

                time (&rawtime);
                timeinfo = localtime(&rawtime);

                strftime(buffer,sizeof(buffer),"%d/%m/%Y %H:%M:%S",timeinfo);
                
                strcpy(pContext->szPdfName, buffer);

                pContext->szPdfReasonLabel[0] = 0;
                pContext->szPdfNameLabel[0] = 0;
                
                delete pCertificate;
            }
            
        }
        sigGen.InitSignature(pContext->nPdfPage, pContext->fPdfLeft, pContext->fPdfBottom, pContext->fPdfWidth, pContext->fPdfHeight, pContext->szPdfReason, pContext->szPdfReasonLabel, pContext->szPdfName,pContext->szPdfNameLabel, pContext->szPdfLocation, pContext->szPdfLocationLabel, sigName.c_str(), pContext->szPdfSubfilter, pContext->szPdfImagePath, pContext->szPdfDescription, NULL, NULL);
    }
    else
    {
        sigGen.InitSignature(0, pContext->szPdfReason, pContext->szPdfReasonLabel, pContext->szPdfName,pContext->szPdfNameLabel, pContext->szPdfLocation, pContext->szPdfLocationLabel, sigName.c_str(), pContext->szPdfSubfilter);
    }
    
    LOG_DBG((0, "sign_pdf", "InitSignature OK"));

    UUCByteArray buffer;
    sigGen.GetBufferForSignature(buffer);

    pContext->pSignatureGenerator->SetData(buffer);

    pContext->pSignatureGenerator->SetHashAlgo(pContext->nHashAlgo);

    LOG_DBG((0, "sign_pdf", "Generate"));

    UUCByteArray signature;
    long nRes = pContext->pSignatureGenerator->Generate(signature, true, pContext->bVerifyCert);
    if(nRes)
    {
        LOG_ERR((0, "sign_pdf", "Generate NOK: %x", nRes));
        return nRes;
    }

    LOG_DBG((0, "sign_pdf", "Generate OK"));

    sigGen.SetSignature((char*)signature.getContent(), signature.getLength());

    LOG_DBG((0, "sign_pdf", "Set Signature OK"));

    UUCByteArray signedPdf;
    sigGen.GetSignedPdf(signedPdf);

    LOG_DBG((0, "sign_pdf", "Get Signed PDF OK"));

    if(pContext->szOutputFile[0] == 0)
    {
        sprintf(pContext->szOutputFile, "%s.pdf",  pContext->szInputFile);
    }

    LOG_DBG((0, "sign_pdf", "OutFile: %s", pContext->szOutputFile));

    FILE* f = fopen(pContext->szOutputFile, "w+b");
    if(!f)
    {
        LOG_ERR((0, "<-- sign_pdf", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szOutputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    fwrite(signedPdf.getContent(), 1, signedPdf.getLength(), f);

    fclose(f);

    LOG_MSG((0, "<-- sign_pdf", "Context: %p", pContext));

    return 0;
}

long verify_pdf(DISIGON_VERIFY_CONTEXT* pContext, UUCByteArray& data, VERIFY_INFO* pVerifyInfo)
{
    PDFVerifier pdfVerifier;

    long nRes = pdfVerifier.Load((char*)data.getContent(), data.getLength());

    if(nRes)
    {
        LOG_ERR((0, "<-- verify_pdf", "Context: %p, Error: %x", pContext, nRes));
        return nRes;
    }

    
    int signatureCount = pdfVerifier.GetNumberOfSignatures();

    pVerifyInfo->pSignerInfos = new SIGNER_INFOS;
    pVerifyInfo->pSignerInfos->nCount = signatureCount;
    //pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO*;
    pVerifyInfo->pSignerInfos->pSignerInfo = new SIGNER_INFO[signatureCount];

    
    for(int i = 0; i < signatureCount; i++)
    {
        
        UUCByteArray sig;
        
#ifndef HP_UX
        SignatureAppearanceInfo sai;
        nRes = pdfVerifier.GetSignature(i, sig, sai);
#else
        nRes = pdfVerifier.GetSignature(i, sig);//, sai);
#endif

        if(nRes)
        {
            //delete *(pVerifyInfo->pSignerInfos->pSignerInfo);
            delete pVerifyInfo->pSignerInfos->pSignerInfo;
            LOG_ERR((0, "<-- verify_pdf", "Context: %p, Error: %x", pContext, nRes));
            return nRes;
        }

        
        CSignedDocument sd(sig.getContent(), sig.getLength());

        CCertificate cert = sd.getSignerCertificate(0);
        CSignerInfo si = sd.getSignerInfo(0);
            
        //SIGNER_INFO* pSI = new SIGNER_INFO;

        SIGNER_INFO* pSI = &(pVerifyInfo->pSignerInfos->pSignerInfo[i]);// = pSI;
        pSI->pCounterSignatures = NULL;
        pSI->nCounterSignatureCount = 0;
        pSI->pRevocationInfo = NULL;
        if(pContext->bVerifyCRL)
            pSI->pRevocationInfo = new REVOCATION_INFO;
        
        char sigType[256];
        pSI->bitmask = pdfVerifier.VerifySignature(i, NULL, sigType, pSI->pRevocationInfo);
        
        //strcpy(pContext->szPdfSubfilter, sigType);

        UUCByteArray subject;
        UUCByteArray issuer;
        cert.getSubject().getNameAsString(subject);
        cert.getIssuer().getNameAsString(issuer);

        string giveName = cert.getSubject().getField(OID_GIVEN_NAME);
        string surname = cert.getSubject().getField(OID_SURNAME);
        string commonName = cert.getSubject().getField(OID_COMMON_NAME);
                
        strcpy(pSI->szCN, commonName.c_str());
        strcpy(pSI->szGIVENNAME, giveName.c_str());
        strcpy(pSI->szSURNAME, surname.c_str());
        
        strcpy(pSI->szDN, (char*)subject.getContent());
        strcpy(pSI->szCADN, (char*)issuer.getContent());

        strcpy(pSI->szSN, ((UUCByteArray*)cert.getSerialNumber().getValue())->toHexString());
        
        try
        {
            CASN1UTCTime signingTime = si.getSigningTime();

            char szTime[MAX_LEN];
            signingTime.getUTCTime(szTime);
            strcpy(pSI->szSigningTime, szTime);

            pSI->b2011Error = (!(pSI->bitmask & VERIFIED_CERT_SHA256)) && (strncmp(szTime, "110630", 6) > 0);

        }
        catch(...)
        {
            strcpy(pSI->szSigningTime, "");
            pSI->b2011Error = false;
        }
        
        CASN1ObjectIdentifier digestOID(si.getDigestAlgorithn().elementAt(0));

        UUCByteArray oid;
        digestOID.ToOidString(oid);
        strcpy(pSI->szDigestAlgorithm, (char*)oid.getContent());

        CASN1Sequence certExtensions(cert.getExtensions());
        CASN1Sequence extensions = certExtensions.elementAt(0);
        int count = extensions.size();
        pSI->nExtensionsCount = count;
        pSI->pszExtensions = new char*[count];
        for(int j = 0; j < count; j++)
        {
            CASN1Sequence extension = extensions.elementAt(j);
            CASN1ObjectIdentifier extoid = extension.elementAt(0);
            CASN1OctetString value(extension.elementAt(1));
            
            UUCByteArray oidName;
            extoid.ToOidString(oidName);
            const char* szoid = g_mapOIDProps.getProperty((char*)oidName.getContent(), (char*)oidName.getContent());
            const char* hexval = ((UUCByteArray*)value.getValue())->toHexString();
            char* szAux = new char[strlen(szoid) + strlen(hexval) + 5];
            sprintf(szAux, "%s:%s", szoid, hexval);
            pSI->pszExtensions[j] = new char[strlen(szAux) + 1];
            strcpy(pSI->pszExtensions[j], szAux);
            delete szAux;
        }


        cert.getExpiration().getUTCTime(pSI->szExpiration);
        cert.getFrom().getUTCTime(pSI->szValidFrom);
        //pSI->pCertificate = new  CCertificate(cert);

        UUCByteArray certificate;
        cert.toByteArray(certificate);

        pSI->nCertLen = certificate.getLength();
        pSI->pCertificate = new BYTE[pSI->nCertLen];
        memcpy(pSI->pCertificate, certificate.getContent(), pSI->nCertLen);
        // Se hai percorsi CA nel contesto, mettili qui (altrimenti lascia nullptr)
        
        const char* ca_file = nullptr;   // es: pContext->szCAFile;
        const char* ca_path = nullptr;   // es: pContext->szCAPath;
        const char* extra_pem = nullptr; // es: pContext->pExtraCABundlePEM;

        // 1) Tempo di verifica: usa la signingTime se presente, altrimenti "adesso"
        const char* verify_time = (pSI->szSigningTime[0] ? pSI->szSigningTime : nullptr);

        int chain_ok = verify_chain_from_der_at_time(
            certificate.getContent(),
            certificate.getLength(),
            ca_file, ca_path, extra_pem,
            verify_time
        );

        if (chain_ok) {
            pSI->bitmask |= VERIFIED_CERT_CHAIN;
        } else {
            pSI->bitmask &= ~VERIFIED_CERT_CHAIN;
            LOG_ERR((0, "verify_pdf", "Certificate chain: FAIL (signer %d)", i));
        }

        // 2) VALIDITY esplicita (indipendente dal pdfVerifier)
        //    Se verify_time==nullptr, confrontiamo con l'ora corrente.
        //    Usiamo OpenSSL per confrontare notBefore/notAfter con un time_t scelto.
        {
            // Costruisci X509 per leggere le date
            const unsigned char* p = certificate.getContent();
            X509* leaf = d2i_X509(nullptr, &p, certificate.getLength());
            bool timeOK = false;
            if (leaf) {
                // scegli il time_t di verifica
                time_t tt = time(nullptr);
                if (verify_time && verify_time[0]) {
                    // parser “robusto” stile ASN.1 (YYMMDDhhmmssZ o YYYYMMDDhhmmssZ)
                    time_t parsed{};
                    if (parse_asn1_like_utc(verify_time, parsed)) tt = parsed;
                }

                // Confronta notBefore/notAfter con tt
                const ASN1_TIME* nb = X509_get0_notBefore(leaf);
                const ASN1_TIME* na = X509_get0_notAfter(leaf);
                // OpenSSL helper: <0 se nb > tt (non ancora valido), >0 se na < tt (scaduto)
                int tooEarly = X509_cmp_time(nb, &tt); // >0 => nb > tt (non valido ancora)
                int tooLate  = X509_cmp_time(na, &tt); // <0 => na < tt (scaduto)
                timeOK = (tooEarly <= 0) && (tooLate >= 0);
                X509_free(leaf);
            }
            if (timeOK)  pSI->bitmask |=  VERIFIED_CERT_VALIDITY;
            else         pSI->bitmask &= ~VERIFIED_CERT_VALIDITY;
        }
        if(si.hasTimeStampToken())
        {
            CTimeStampToken tst = si.getTimeStampToken();

            TS_INFO* pTSInfo = new TS_INFO;

            CCertificate tsacert(tst.getCertificates().elementAt(0));

            UUCByteArray subject;
            UUCByteArray issuer;
            
            tsacert.getSubject().getNameAsString(subject);
            tsacert.getIssuer().getNameAsString(issuer);

            strcpy(pTSInfo->signerInfo.szDN, (char*)subject.getContent());
            strcpy(pTSInfo->signerInfo.szCADN, (char*)issuer.getContent());

            CTSTInfo tstInfo(tst.getTSTInfo());

            CASN1ObjectIdentifier digestOID(tstInfo.getDigestAlgorithn().elementAt(0));
            UUCByteArray oid;
            digestOID.ToOidString(oid);
            strcpy(pTSInfo->signerInfo.szDigestAlgorithm, (char*)oid.getContent());

            strcpy(pTSInfo->signerInfo.szSN, ((UUCByteArray*)tstInfo.getSerialNumber().getValue())->toHexString());

            tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

            tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
            tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);
            //pTSInfo->signerInfo.pCertificate = new  CCertificate(tsacert);

            UUCByteArray certificate;
            tsacert.toByteArray(certificate);

            pTSInfo->signerInfo.nCertLen = certificate.getLength();
            pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
            memcpy(pTSInfo->signerInfo.pCertificate, certificate.getContent(), pTSInfo->signerInfo.nCertLen);

            pTSInfo->signerInfo.pRevocationInfo = NULL;
            if(pContext->bVerifyCRL)
                pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;
        
            pTSInfo->signerInfo.bitmask = tst.verify(pTSInfo->signerInfo.pRevocationInfo);

            pSI->pTimeStamp = pTSInfo;
        }
        else
        {
            pSI->pTimeStamp = NULL;
        }

        //pVerifyInfo->pSignerInfos->pSignerInfo[i] = pSI;

    }

    LOG_MSG((0, "<-- verify_pdf", "Context: %p", pContext));

    return 0;

}

long verify_pdf(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_pdf", "Context: %p", pContext));

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- verify_pdf", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);
    
    return verify_pdf(pContext, data, pVerifyInfo);
}


long verify_tsd(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_tsd", "Context: %p", pContext));

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- verify_tsd", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);

    BYTE* pbContent;
    int len = data.getLength();
    char* szDecoded = NULL;
    if(data.getContent()[0] != 0x30)
    {
        // base64
        char* szBase64Content;
        char* szContent = new char[len + 1];
        char* szEncoded = new char[len + 1];

        memcpy(szContent, data.getContent(), len);
        szContent[len] = 0;
        char* pos = strstr(szContent, "--");
        
        if(pos != NULL) // header PEM da eliminare
        {
            szBase64Content = strtok(szContent, "\r\n");
            szBase64Content = strtok(NULL, "----");
        }
        else
        {
            szBase64Content = szContent;
        }
        
        strcpy(szEncoded, "");
        char* szPart = strtok(szBase64Content, "\r\n");
        while(szPart)
        {
            strcat(szEncoded, szPart);
            szPart = strtok(NULL, "\r\n");
        }

        size_t decLen = base64_decoded_size(strlen(szEncoded));
        szDecoded = base64_decode(szEncoded);

        pbContent = (BYTE*)szDecoded;
        len = decLen;
    }
    else
    {
        pbContent = (BYTE*)data.getContent();
        len = data.getLength();
    }

    UUCBufferedReader reader(pbContent, len);
    CTimeStampData tsd(reader);
    CTimeStampToken tst(tsd.getTimeStampToken());
    
    if(szDecoded)
        free(szDecoded);

    CASN1OctetString octetString(tsd.getTimeStampDataContent());
    UUCByteArray content;
    if(octetString.getTag() == 0x24) // contructed octet string
    {
        CASN1Sequence contentArray(octetString);
        int size = contentArray.size();
        for(int i = 0; i < size; i++)
        {
            content.append(contentArray.elementAt(i).getValue()->getContent(), contentArray.elementAt(i).getLength());
        }
    }
    else
    {
        content.append(octetString.getValue()->getContent(), octetString.getLength());
    }

    try
    {
        CSignedDocument sd(content.getContent(), content.getLength());

        long nRet = verify_signed_document(pContext, sd, pVerifyInfo);
        if(nRet)
            return nRet;

        LOG_DBG((0, "verify_tsd", "Signature Count: %d", pVerifyInfo->pSignerInfos->nCount));

//        pVerifyInfo->pSignerInfos->pSignerInfo[0]->pTimeStamp = new TS_INFO;

//        return verifyTST(tst, (TS_INFO*)pVerifyInfo->pSignerInfos->pSignerInfo[0]->pTimeStamp, pContext->bVerifyCRL);
    }
    catch(...)
    {
    
    }

    //LOG_MSG((0, "verify_tsd", "pVerifyInfo->pSignerInfos: %p", pVerifyInfo->pSignerInfos));

    pVerifyInfo->pTSInfo = new TS_INFO;

    // TEST
    //LOG_MSG((0, "verify_tsd", "pVerifyInfo->pSignerInfos: %p", pVerifyInfo->pSignerInfos));

    //LOG_DBG((0, "verify_tsd", "Count: %d", pVerifyInfo->pSignerInfos->nCount));

    //SIGNER_INFO* pSignerInfo = pVerifyInfo->pSignerInfos->pSignerInfo[0];

    //LOG_DBG((0, "verify_tsd", "pSignerInfo SN: %s", pSignerInfo->szSN));
    /////////////////////////
        
    return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);

}

long verify_tst(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_tst", "Context: %p", pContext));

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- verify_tst", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);

    pVerifyInfo->pTSInfo = new TS_INFO;

    UUCBufferedReader reader(data);
    CTimeStampToken tst(reader);

    return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);
}

long verify_tsr(DISIGON_VERIFY_CONTEXT* pContext, VERIFY_INFO* pVerifyInfo)
{
    LOG_MSG((0, "--> verify_tsr", "Context: %p", pContext));

    UUCByteArray data;
    BYTE buffer[BUFFERSIZE];
    int nRead = 0;

    FILE* f = fopen(pContext->szInputFile, "rb");
    if(!f)
    {
        LOG_ERR((0, "<-- verify_tsr", "Context: %p, Error: DISIGON_ERROR_FILE_NOT_FOUND, file: %s", pContext, pContext->szInputFile));
        return DISIGON_ERROR_FILE_NOT_FOUND;
    }

    while(((nRead = fread(buffer, 1, BUFFERSIZE, f)) > 0))
    {
        data.append(buffer, nRead);
    }

    fclose(f);

    pVerifyInfo->pTSInfo = new TS_INFO;

    BYTE* pbContent;
    int len = data.getLength();
    char* szDecoded = NULL;
    if(data.getContent()[0] != 0x30)
    {
        // base64
        char* szBase64Content;
        char* szContent = new char[len + 1];
        char* szEncoded = new char[len + 1];

        memcpy(szContent, data.getContent(), len);
        szContent[len] = 0;
        char* pos = strstr(szContent, "--");
        
        if(pos != NULL) // header PEM da eliminare
        {
            szBase64Content = strtok(szContent, "\r\n");
            szBase64Content = strtok(NULL, "----");
        }
        else
        {
            szBase64Content = szContent;
        }
        
        strcpy(szEncoded, "");

        char* szPart = strtok(szBase64Content, "\r\n");
        while(szPart)
        {
            strcat(szEncoded, szPart);
            szPart = strtok(NULL, "\r\n");
        }

        size_t decLen = base64_decoded_size(strlen(szEncoded));
        szDecoded = base64_decode(szEncoded);

        pbContent = (BYTE*)szDecoded;
        len = decLen;
    }
    else
    {
        pbContent = (BYTE*)data.getContent();
        len = data.getLength();
    }

    CTimeStampResponse tsr(pbContent, len);
    CTimeStampToken tst(tsr.getTimeStampToken());

    if(szDecoded)
        free(szDecoded);
    
    return verifyTST(tst, pVerifyInfo->pTSInfo, pContext->bVerifyCRL);

}

long verifyTST(CTimeStampToken& tst, TS_INFO* pTSInfo, BOOL bVerifyCRL)
{
    LOG_MSG((0, "--> verifyTST", "TS_INFO: %p", pTSInfo));

    pTSInfo->signerInfo.pCounterSignatures = NULL;
    pTSInfo->signerInfo.nCounterSignatureCount = 0;
    pTSInfo->signerInfo.szCertificateV2[0] = 0;

    CCertificate tsacert(tst.getCertificates().elementAt(0));

    tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
    tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);
    //pTSInfo->signerInfo.pCertificate = new  CCertificate(tsacert);


    UUCByteArray subject;
    UUCByteArray issuer;
    
    tsacert.getSubject().getNameAsString(subject);
    tsacert.getIssuer().getNameAsString(issuer);

    strcpy(pTSInfo->signerInfo.szDN, (char*)subject.getContent());
    strcpy(pTSInfo->signerInfo.szCADN, (char*)issuer.getContent());

        
    CTSTInfo tstInfo(tst.getTSTInfo());
    tstInfo.getUTCTime().getUTCTime(pTSInfo->szTimestamp);

    strcpy(pTSInfo->signerInfo.szSN, ((UUCByteArray*)tsacert.getSerialNumber().getValue())->toHexString());
    strcpy(pTSInfo->szTimeStampSerial, ((UUCByteArray*)tstInfo.getSerialNumber().getValue())->toHexString());

    tsacert.getExpiration().getUTCTime(pTSInfo->signerInfo.szExpiration);
    tsacert.getFrom().getUTCTime(pTSInfo->signerInfo.szValidFrom);
    //pTSInfo->signerInfo.pCertificate = new  CCertificate(tsacert);

    UUCByteArray* certificate = (UUCByteArray*)tsacert.getValue();

    pTSInfo->signerInfo.nCertLen = certificate->getLength();
    pTSInfo->signerInfo.pCertificate = new BYTE[pTSInfo->signerInfo.nCertLen];
    memcpy(pTSInfo->signerInfo.pCertificate, certificate->getContent(), pTSInfo->signerInfo.nCertLen);

    pTSInfo->signerInfo.pRevocationInfo = NULL;

    if(bVerifyCRL)
        pTSInfo->signerInfo.pRevocationInfo = new REVOCATION_INFO;

    pTSInfo->signerInfo.bitmask = tst.verify(pTSInfo->signerInfo.pRevocationInfo);

    // MessageImprint
    CASN1Sequence messageImprint = tstInfo.getMessageImprint();
        
    // algo
    CAlgorithmIdentifier algoid(messageImprint.elementAt(0));
    CASN1ObjectIdentifier timeStampImprintAlgorithm(algoid.elementAt(0));
    UUCByteArray oid1;
    timeStampImprintAlgorithm.ToOidString(oid1);
    strcpy(pTSInfo->szTimeStampImprintAlgorithm, (char*)oid1.getContent());

    // imprint b64
    CASN1OctetString mimprint = messageImprint.elementAt(1);
    const UUCByteArray* val = mimprint.getValue();

    size_t encLen = base64_encoded_size(val->getLength());
    char* szEncoded = base64_encode((char*)val->getContent(), val->getLength());

    strcpy(pTSInfo->szTimeStampMessageImprint, szEncoded);

    free(szEncoded);

    CASN1ObjectIdentifier digestOID(tstInfo.getDigestAlgorithn().elementAt(0));
    UUCByteArray oid;
    digestOID.ToOidString(oid);
    strcpy(pTSInfo->signerInfo.szDigestAlgorithm, (char*)oid.getContent());

    pTSInfo->signerInfo.nExtensionsCount = 0;

    LOG_MSG((0, "<-- verifyTST", "TS_INFO: %p", pTSInfo));

    return 0;
}


int get_file_type(char* szFileName)
{
    char* pos = strrchr(szFileName, '.');
    if(pos)
    {
        const char* szExt = pos;
        if(STRICMP(szExt, ".p7m") == 0)
            return DISIGON_FILETYPE_P7M;
        else if(STRICMP(szExt, ".m7m") == 0)
            return DISIGON_FILETYPE_M7M;
        else if(STRICMP(szExt, ".pdf") == 0)
            return DISIGON_FILETYPE_PDF;
        else if(STRICMP(szExt, ".tsr") == 0)
            return DISIGON_FILETYPE_TSR;
        else if(STRICMP(szExt, ".tsd") == 0)
            return DISIGON_FILETYPE_TSD;
        else if(STRICMP(szExt, ".xml") == 0)
            return DISIGON_FILETYPE_XML;
        else if(STRICMP(szExt, ".tst") == 0)
            return DISIGON_FILETYPE_TST;
        else
            return DISIGON_FILETYPE_PLAINTEXT;
    }
    
    return DISIGON_FILETYPE_PLAINTEXT;
}

