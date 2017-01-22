#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>

#define ascii2bcd(c)		((c==0)?0:(((c>='A')&&(c<='F'))?(c-0x37):(((c>='a')&&(c<='f'))?(c-0x57):(c-0x30))))

typedef struct __RSAPrivateKey
{
	char modulus[512 + 1];
	char publicExponent[16 + 1];
	char privateExponent[512 + 1];
	char prime1[512 + 1];
	char prime2[512 + 1];
	char exponent1[512 + 1];
	char exponent2[512 + 1];
	char coefficient[512 + 1];
} STRSAPrivateKey;

const static char BASE64_ALPHABET [64] = 
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', //   0 -   9
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', //  10 -  19
	'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', //  20 -  29
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', //  30 -  39
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', //  40 -  49
	'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', //  50 -  59
	'8', '9', '+', '/'                  //  60 -  63
};

void AsciiToBCD(unsigned char *pascii, unsigned char *phex, int len)
{
	int i;
	int a,b;

	for (i=0; i<len/2; i++)
	{
		a = ((int)ascii2bcd(pascii[2*i])) << 4;
		b = (int)ascii2bcd(pascii[2*i+1]) ;

		phex[i] = a + b;
	}
}

void savePEM(unsigned char *data, unsigned int length, char *path)
{
	FILE *fp = NULL;
	fp = fopen(path, "wb");
	if(fp == NULL)
	{
		return;
	}
	fwrite(data, length, 1, fp);
	fclose(fp);
	fp = NULL;
}

void EncodeByteTriple (const char* p_pInputBuffer, unsigned int InputCharacters, char* p_pOutputBuffer)
{
	unsigned int mask = 0xfc000000;
	unsigned int buffer = 0;

	char* temp = (char*) &buffer;
	temp [3] = p_pInputBuffer [0];
	if (InputCharacters > 1)
		temp [2] = p_pInputBuffer [1];
	if (InputCharacters > 2)
		temp [1] = p_pInputBuffer [2];

	switch (InputCharacters)
	{
	case 3:
		{
			p_pOutputBuffer [0] = BASE64_ALPHABET [(buffer & mask) >> 26];
			buffer = buffer << 6;
			p_pOutputBuffer [1] = BASE64_ALPHABET [(buffer & mask) >> 26];
			buffer = buffer << 6;
			p_pOutputBuffer [2] = BASE64_ALPHABET [(buffer & mask) >> 26];
			buffer = buffer << 6;
			p_pOutputBuffer [3] = BASE64_ALPHABET [(buffer & mask) >> 26];
			break;
		}
	case 2:
		{
			p_pOutputBuffer [0] = BASE64_ALPHABET [(buffer & mask) >> 26];
			buffer = buffer << 6;
			p_pOutputBuffer [1] = BASE64_ALPHABET [(buffer & mask) >> 26];
			buffer = buffer << 6;
			p_pOutputBuffer [2] = BASE64_ALPHABET [(buffer & mask) >> 26];
			p_pOutputBuffer [3] = '=';
			break;
		}
	case 1:
		{
			p_pOutputBuffer [0] = BASE64_ALPHABET [(buffer & mask) >> 26];
			buffer = buffer << 6;
			p_pOutputBuffer [1] = BASE64_ALPHABET [(buffer & mask) >> 26];
			p_pOutputBuffer [2] = '=';
			p_pOutputBuffer [3] = '=';
			break;
		}
	}
}

unsigned int CalculateRecquiredEncodeOutputBufferSize (unsigned int p_InputByteCount)
{
	div_t result = div (p_InputByteCount, 3);

	unsigned int RecquiredBytes = 0;
	if (result.rem == 0)
	{
		// Number of encoded characters
		RecquiredBytes = result.quot * 4;

		// CRLF -> "\r\n" each 76 characters
		result = div (RecquiredBytes, 76);
		RecquiredBytes += result.quot * 2;

		// Terminating null for the Encoded String
		RecquiredBytes += 1;

		return RecquiredBytes;
	}
	else
	{
		// Number of encoded characters
		RecquiredBytes = result.quot * 4 + 4;

		// CRLF -> "\r\n" each 76 characters
		result = div (RecquiredBytes, 76);
		RecquiredBytes += result.quot * 2;

		// Terminating null for the Encoded String
		RecquiredBytes += 1;

		return RecquiredBytes;
	}
}

unsigned int CreateMatchingEncodingBuffer (unsigned int p_InputByteCount, char** p_ppEncodingBuffer)
{
	unsigned int Size = CalculateRecquiredEncodeOutputBufferSize (p_InputByteCount);
	(*p_ppEncodingBuffer) = (char*) malloc (Size);
	memset (*p_ppEncodingBuffer, 0, Size);
	return Size;
}

void EncodeBuffer(const char* p_pInputBuffer, unsigned int p_InputBufferLength, char* p_pOutputBufferString)
{
	unsigned int FinishedByteQuartetsPerLine = 0;
	unsigned int InputBufferIndex  = 0;
	unsigned int OutputBufferIndex = 0;

	memset (p_pOutputBufferString, 0, CalculateRecquiredEncodeOutputBufferSize (p_InputBufferLength));

	while (InputBufferIndex < p_InputBufferLength)
	{
		if (p_InputBufferLength - InputBufferIndex <= 2)
		{
			FinishedByteQuartetsPerLine ++;
			EncodeByteTriple (p_pInputBuffer + InputBufferIndex, p_InputBufferLength - InputBufferIndex, p_pOutputBufferString + OutputBufferIndex);
			break;
		}
		else
		{
			FinishedByteQuartetsPerLine++;
			EncodeByteTriple (p_pInputBuffer + InputBufferIndex, 3, p_pOutputBufferString + OutputBufferIndex);
			InputBufferIndex  += 3;
			OutputBufferIndex += 4;
		}

		if (FinishedByteQuartetsPerLine == 19)
		{
			p_pOutputBufferString [OutputBufferIndex] = '\r';
			//			p_pOutputBufferString [OutputBufferIndex+1] = '\n';
			//			p_pOutputBufferString += 2;
			p_pOutputBufferString += 1;
			FinishedByteQuartetsPerLine = 0;
		}
	}
}

unsigned int EncodeFile (const char* p_pSourceFileName, char* p_pEncodedBuffer, int outputBufLength)
{
	char InputBuffer [19 * 3] = {0};
	char* pOutputBuffer = NULL;
	unsigned int ReadBytes = 0;
	FILE *fp = NULL;
	fp = fopen(p_pSourceFileName, "rb");
	if(fp == NULL)
	{
		return -1;
	}

	CreateMatchingEncodingBuffer (sizeof (InputBuffer), &pOutputBuffer);

	if (pOutputBuffer == 0)
		return -2;

	while ((ReadBytes = fread(InputBuffer, sizeof(char), sizeof(InputBuffer), fp)) != 0)
	{
		EncodeBuffer (InputBuffer, ReadBytes, pOutputBuffer);
		strcat(p_pEncodedBuffer, pOutputBuffer);
	}

	fclose(fp);
	fp = NULL;

	return 0;
}

/**
    function : 生成RSA公私钥对
    param :
          pstRSAKey - RSA私钥结构体
		  pOutPrivEncodeBuf - RSA private key
		  pOutPubEncodeBuf - RSA public key
*/
void generateRSAKey(STRSAPrivateKey *pstRSAKey, char *pOutPrivEncodeBuf, char *pOutPubEncodeBuf)
{
	unsigned char TLL_PRIVATE_SEQUENCE[] = {0x30, 0x82, 0x00, 0x00};
	unsigned char TLL_PUBLIC_SEQUENCE[] = {0x30, 0x82, 0x00, 0x00};
	unsigned char TL_VERSION[] = {0x02, 0x01, 0x00};
	unsigned char TLL_MODULUS[] = {0x02, 0x82, 0x00, 0x00};
	unsigned char TL_PublicExponent[] = {0x02, 0x00};
	unsigned char TLL_PrivateExponent[] = {0x02, 0x82, 0x00, 0x00};
	unsigned char TL_Prime1[] = {0x02, 0x81, 0x00};
	unsigned char TL_Prime2[] = {0x02, 0x81, 0x00};
	unsigned char TL_Exponent1[] = {0x02, 0x81, 0x00};
	unsigned char TL_Exponent2[] = {0x02, 0x81, 0x00};
	unsigned char TL_Coefficient[] = {0x02, 0x81, 0x00};
	unsigned char TLL_OTHER_1[] = {0x03, 0x82, 0x00, 0x00};
	unsigned char TLL_OTHER_2[] = {0x00, 0x30, 0x82, 0x00, 0x00};

	unsigned char szPrivateKeyBuf[1024 * 2] = {0};
	unsigned char szPubKeyBuf[512 * 3] = {0};
	unsigned char *pOtherHead = "300d06092a864886f70d0101010500";
 	char *pPrivateKeyPEMPath = "/home/mcs/temp/privateKey.pem";
 	char *pPubKeyPEMPath = "/home/mcs/temp/publicKey.pem";
	unsigned int privateIndex = 0, publicIndex = 0;

	unsigned char szModulusBCD[512] = {0};
	unsigned char szPubExponentBCD[16] = {0};
	unsigned char szPrivExponentBCD[512] = {0};
	unsigned char szPrime1BCD[512] = {0};
	unsigned char szPrime2BCD[512] = {0};
	unsigned char szExponent1BCD[512] = {0};
	unsigned char szExponent2BCD[512] = {0};
	unsigned char szCoefficientBCD[512] = {0};
	unsigned char szOtherHeadBCD[20] = {0};
	unsigned char szPrivKeyPEMBuf[1024 * 4] = {0};
	unsigned char szPubKeyPEMBuf[1024] = {0};

	int modulusLen = 0;
	int publicExponentLen = 0;
	int privateExponentLen = 0;
	int prime1Len = 0;
	int prime2Len = 0;
	int exponent1Len = 0;
	int exponent2Len = 0;
	int coefficientLen = 0;
	int privateKeyDataLen = 0;
	int pubKeyDataLen = 0;
	int index = 0;

	int body_1_Len = 0;
	int body_2_Len = 0;
	unsigned char szBody1[1024] = {0};
	unsigned char szBody2[1024] = {0};
	char base64PriRes[1024 * 2] = {0};
	char base64PubRes[1024 * 2] = {0};

    assert(pstRSAKey != NULL);

	memset(szPrivateKeyBuf, 0, sizeof(szPrivateKeyBuf));
	memset(szPubKeyBuf, 0, sizeof(szPubKeyBuf));

	//Version TLV L = 0
	memcpy(szPrivateKeyBuf, TL_VERSION, sizeof(TL_VERSION));
	privateIndex += sizeof(TL_VERSION);

	//Modulus TLV
	modulusLen = (strlen(pstRSAKey->modulus) + 2) / 2;
	TLL_MODULUS[2] = (unsigned char)(modulusLen / 0x100);
	TLL_MODULUS[3] = (unsigned char)(modulusLen % 0x100);

	memcpy(szPrivateKeyBuf + privateIndex, TLL_MODULUS, sizeof(TLL_MODULUS));
	privateIndex += sizeof(TLL_MODULUS);
	memcpy(szPubKeyBuf, TLL_MODULUS, sizeof(TLL_MODULUS));
	publicIndex += sizeof(TLL_MODULUS);

	privateIndex ++;
	publicIndex ++;

	AsciiToBCD((unsigned char *)pstRSAKey->modulus, szModulusBCD, modulusLen * 2 - 2);
	memcpy(szPrivateKeyBuf + privateIndex, szModulusBCD, modulusLen - 1);
	privateIndex += modulusLen - 1;
	memcpy(szPubKeyBuf + publicIndex, szModulusBCD, modulusLen - 1);
	publicIndex += modulusLen - 1;

	//publicExponent TLV
	publicExponentLen = strlen(pstRSAKey->publicExponent) / 2;
	if(publicExponentLen > 0)
	{
		int m = 0;
		unsigned char szTemp[16] = {0};
		unsigned char szTempBCD[16] = {0};

		index = 0;
		TL_PublicExponent[1] = (unsigned char)publicExponentLen;
		memcpy(szPrivateKeyBuf + privateIndex, TL_PublicExponent, sizeof(TL_PublicExponent));
		privateIndex += sizeof(TL_PublicExponent);

		AsciiToBCD((unsigned char *)pstRSAKey->publicExponent, szPubExponentBCD, publicExponentLen * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szPubExponentBCD, publicExponentLen);
		privateIndex += publicExponentLen;

		//计算Pubkey，抛弃0x00
		//找到第一个不为0x00的下标
		for(m = 0; m < publicExponentLen; m++)
		{
			if(szPubExponentBCD[m] != 0x00)
			{
				break;
			}
			index ++;
		}

		publicExponentLen = publicExponentLen - index;
		TL_PublicExponent[1] = (unsigned char)publicExponentLen;
		memcpy(szPubKeyBuf + publicIndex, TL_PublicExponent, sizeof(TL_PublicExponent));
		publicIndex += sizeof(TL_PublicExponent);

		memcpy(szTemp, pstRSAKey->publicExponent + index * 2, publicExponentLen * 2);
		AsciiToBCD(szTemp, szTempBCD, publicExponentLen * 2);
		memcpy(szPubKeyBuf + publicIndex, szTempBCD, publicExponentLen);
		publicIndex += publicExponentLen;

		index = 0;
	}

	//privateExponent TLLV
	privateExponentLen = strlen(pstRSAKey->privateExponent) / 2;
	if(privateExponentLen > 0)
	{
		TLL_PrivateExponent[2] = (unsigned char)(privateExponentLen / 0x100);
		TLL_PrivateExponent[3] = (unsigned char)(privateExponentLen % 0x100);
		memcpy(szPrivateKeyBuf + privateIndex, TLL_PrivateExponent, sizeof(TLL_PrivateExponent));
		privateIndex += sizeof(TLL_PrivateExponent);

		AsciiToBCD((unsigned char *)pstRSAKey->privateExponent, szPrivExponentBCD, privateExponentLen * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szPrivExponentBCD, privateExponentLen);
		privateIndex += privateExponentLen;
	}

	//prime1 TLV
	prime1Len = strlen(pstRSAKey->prime1) / 2;
	if(prime1Len > 0)
	{
		TL_Prime1[2] = (unsigned char)prime1Len;
		memcpy(szPrivateKeyBuf + privateIndex, TL_Prime1, sizeof(TL_Prime1));
		privateIndex += sizeof(TL_Prime1);

		AsciiToBCD((unsigned char *)pstRSAKey->prime1, szPrime1BCD, prime1Len * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szPrime1BCD, prime1Len);
		privateIndex += prime1Len;
	}

	//prime2 TLV
	prime2Len = strlen(pstRSAKey->prime2) / 2;
	if(prime2Len > 0)
	{
		TL_Prime2[2] = (unsigned char)prime2Len;
		memcpy(szPrivateKeyBuf + privateIndex, TL_Prime2, sizeof(TL_Prime2));
		privateIndex += sizeof(TL_Prime2);

		AsciiToBCD((unsigned char *)pstRSAKey->prime2, szPrime2BCD, prime2Len * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szPrime2BCD, prime2Len);
		privateIndex += prime2Len;
	}

	//exponent1 TLV
	exponent1Len = strlen(pstRSAKey->exponent1) / 2;
	if(exponent1Len > 0)
	{
		TL_Exponent1[2] = (unsigned char)exponent1Len;
		memcpy(szPrivateKeyBuf + privateIndex, TL_Exponent1, sizeof(TL_Exponent1));
		privateIndex += sizeof(TL_Exponent1);

		AsciiToBCD((unsigned char *)pstRSAKey->exponent1, szExponent1BCD, exponent1Len * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szExponent1BCD, exponent1Len);
		privateIndex += exponent1Len;
	}

	//exponent2 TLV
	exponent2Len = strlen(pstRSAKey->exponent2) / 2;
	if(exponent2Len > 0)
	{
		TL_Exponent2[2] = (unsigned char)exponent2Len;
		memcpy(szPrivateKeyBuf + privateIndex, TL_Exponent2, sizeof(TL_Exponent2));
		privateIndex += sizeof(TL_Exponent2);

		AsciiToBCD((unsigned char *)pstRSAKey->exponent2, szExponent2BCD, exponent2Len * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szExponent2BCD, exponent2Len);
		privateIndex += exponent2Len;
	}

	//coefficient TLV
	coefficientLen = strlen(pstRSAKey->coefficient) / 2;
	if(coefficientLen > 0)
	{
		TL_Coefficient[2] = (unsigned char)coefficientLen;
		memcpy(szPrivateKeyBuf + privateIndex, TL_Coefficient, sizeof(TL_Coefficient));
		privateIndex += sizeof(TL_Coefficient);

		AsciiToBCD((unsigned char *)pstRSAKey->coefficient, szCoefficientBCD, coefficientLen * 2);
		memcpy(szPrivateKeyBuf + privateIndex, szCoefficientBCD, coefficientLen);
		privateIndex += coefficientLen;
	}

	privateKeyDataLen = privateIndex;
	pubKeyDataLen = publicIndex;
	index = 0;

	TLL_PRIVATE_SEQUENCE[2] = (unsigned char)(privateKeyDataLen / 0x100);
	TLL_PRIVATE_SEQUENCE[3] = (unsigned char)(privateKeyDataLen % 0x100);

	memcpy(szPrivKeyPEMBuf, TLL_PRIVATE_SEQUENCE, sizeof(TLL_PRIVATE_SEQUENCE));
	index += sizeof(TLL_PRIVATE_SEQUENCE);
	memcpy(szPrivKeyPEMBuf + index, szPrivateKeyBuf, privateKeyDataLen);
	index = 0;

	body_2_Len = pubKeyDataLen;

	TLL_OTHER_2[3] = (unsigned char)(body_2_Len / 0x100);
	TLL_OTHER_2[4] = (unsigned char)(body_2_Len % 0x100);

	memcpy(szBody2, TLL_OTHER_2, sizeof(TLL_OTHER_2));
	index += sizeof(TLL_OTHER_2);
	memcpy(szBody2 + index, szPubKeyBuf, pubKeyDataLen);
	index += pubKeyDataLen;

	body_1_Len = index;
	TLL_OTHER_1[2] = (unsigned char)(body_1_Len / 0x100);
	TLL_OTHER_1[3] = (unsigned char)(body_1_Len % 0x100);

	index = 0;
	AsciiToBCD(pOtherHead, szOtherHeadBCD, strlen((char *)pOtherHead));

	memcpy(szBody1, szOtherHeadBCD, strlen((char *)pOtherHead) / 2);
	index += strlen((char *)pOtherHead) / 2;
	memcpy(szBody1 + index, TLL_OTHER_1, sizeof(TLL_OTHER_1));
	index += sizeof(TLL_OTHER_1);
	memcpy(szBody1 + index, szBody2, pubKeyDataLen + sizeof(TLL_OTHER_2));
	index += pubKeyDataLen + sizeof(TLL_OTHER_2);

	TLL_PUBLIC_SEQUENCE[2] = (unsigned char)(index / 0x100);
	TLL_PUBLIC_SEQUENCE[3] = (unsigned char)(index % 0x100);
	index = 0;

	memcpy(szPubKeyPEMBuf, TLL_PUBLIC_SEQUENCE, sizeof(TLL_PUBLIC_SEQUENCE));
	index += sizeof(TLL_PUBLIC_SEQUENCE);
	memcpy(szPubKeyPEMBuf + index, szBody1, (TLL_PUBLIC_SEQUENCE[2] * 0x100 + TLL_PUBLIC_SEQUENCE[3]));

#if 0
	if(strlen(pPrivateKeyPEMPath) > 0 && strlen(pPubKeyPEMPath) > 0)
	{
		savePEM(szPrivKeyPEMBuf, privateKeyDataLen + sizeof(TLL_PRIVATE_SEQUENCE), pPrivateKeyPEMPath);
		savePEM(szPubKeyPEMBuf, TLL_PUBLIC_SEQUENCE[2] * 0x100 + TLL_PUBLIC_SEQUENCE[3] + sizeof(TLL_PUBLIC_SEQUENCE), pPubKeyPEMPath);
	}

	//base64 encode
	//private key base64
	index = 0;
	EncodeFile(pPrivateKeyPEMPath, base64PriRes, sizeof(base64PriRes));
	memcpy(pOutPrivEncodeBuf, "-----BEGIN RSA PRIVATE KEY-----\n", strlen("-----BEGIN RSA PRIVATE KEY-----\n"));
	index += strlen("-----BEGIN RSA PRIVATE KEY-----\n");
	memcpy(pOutPrivEncodeBuf + index, base64PriRes, strlen(base64PriRes));
	index += strlen(base64PriRes);
	memcpy(pOutPrivEncodeBuf + index, "\n-----END RSA PRIVATE KEY-----", strlen("\n-----END RSA PRIVATE KEY-----"));

	//pulic key base64
	index = 0;
	EncodeFile(pPubKeyPEMPath, base64PubRes, sizeof(base64PubRes));
	memcpy(pOutPubEncodeBuf, "-----BEGIN PUBLIC KEY-----\n", strlen("-----BEGIN PUBLIC KEY-----\n"));
	index += strlen("-----BEGIN PUBLIC KEY-----\n");
	memcpy(pOutPubEncodeBuf + index, base64PubRes, strlen(base64PubRes));
	index += strlen(base64PubRes);
	memcpy(pOutPubEncodeBuf + index, "\n-----END PUBLIC KEY-----", strlen("\n-----END PUBLIC KEY-----"));
	
// 	system("rm -rf /home/mcs/temp/privateKey.pem");
// 	system("rm -rf /home/mcs/temp/publicKey.pem");
#else
	//private key base64
	index = 0;
	EncodeBuffer((char *)szPrivKeyPEMBuf, privateKeyDataLen + sizeof(TLL_PRIVATE_SEQUENCE), base64PriRes);
	memcpy(pOutPrivEncodeBuf, "-----BEGIN RSA PRIVATE KEY-----\n", strlen("-----BEGIN RSA PRIVATE KEY-----\n"));
	index += strlen("-----BEGIN RSA PRIVATE KEY-----\n");
	memcpy(pOutPrivEncodeBuf + index, base64PriRes, strlen(base64PriRes));
	index += strlen(base64PriRes);
	memcpy(pOutPrivEncodeBuf + index, "\n-----END RSA PRIVATE KEY-----", strlen("\n-----END RSA PRIVATE KEY-----"));

	//pulic key base64
	index = 0;
	EncodeBuffer((char *)szPubKeyPEMBuf, TLL_PUBLIC_SEQUENCE[2] * 0x100 + TLL_PUBLIC_SEQUENCE[3] + sizeof(TLL_PUBLIC_SEQUENCE), base64PubRes);
	memcpy(pOutPubEncodeBuf, "-----BEGIN PUBLIC KEY-----\n", strlen("-----BEGIN PUBLIC KEY-----\n"));
	index += strlen("-----BEGIN PUBLIC KEY-----\n");
	memcpy(pOutPubEncodeBuf + index, base64PubRes, strlen(base64PubRes));
	index += strlen(base64PubRes);
	memcpy(pOutPubEncodeBuf + index, "\n-----END PUBLIC KEY-----", strlen("\n-----END PUBLIC KEY-----"));
#endif

    return;
}

int main(void)
{
	STRSAPrivateKey stRSAPrivKey;
	char *pModulus = "BCFBBF12422709C4AF1AD6F16BF891AE5120F9F62A450679428610E613A0763721194B4A0705DB210227B18D6C5E02DF82772A32F77927D97CCD33085913DA33F65C0947A21C21D174AC0227E0C8781DBA2379AD038923BAA319A7A91AEA2555BBFD68A3D688DC9AD7312C4DE79D8984109969D0B993A12B34A647ED27421CA9A2CFB40517B2D16FF5B78DB21EA7BE0C49B97210EB982588D8126F52FD050ECE626F3551B5B81B9C512FA5847FF24624E80CAF9DDB3F935D0BD346B7404EFAEB241F81DE05A0AC4FECD5D6B834D2B0B843AC31C055A72F71B5610BE7BDAACDFEB5754386ED3D2E03F4EAC9637C22363C83852ABEE259929B33CE524EF282217F";
	char *pPublicExponent = "00000003";
	char *pPrivateExponent = "7DFD2A0C2C1A06831F6739F647FB0BC98B6B514EC6D8AEFB81AEB5EEB7C04ECF6B6632315A03E76B56C52108F2E9573FAC4F71774FA61A90FDDE220590B7E6CD4EE8062FC168168BA31D56C54085A56926C2511E025B6D2717666FC611F16E3927FE45C28F05E8673A20C833EFBE5BAD6066468B26626B7223198548C4D6BDC546648B572A71DB689F1F78709FC8E2C9C2295A24081959F90A1A2BF2E746312F555C7F9FA23BABD03E03FDCFAECFD8B6A792F23A5F02CC31B534E01098C50390261D1C5575C3F5C4F36B61ED98F647DF0F844AE52646DF4BADC8EBD835CED2738EF4D81DB895D14F905D3DC2B54457488A49FA18FEDBA783FB6C35EAFA0B294B";
	char *pPrime1 = "EDA050129801F88B4318916D8756EC7DA60CBCEBC98656A4B186B308104BB22901D2B34682DDDAE4BDE8D3887AD4133C9D52283C9932C9DB8B86AE30C4684141A8BE2BAAEA89C5E176B424959F691041127A188D041BC5B32C26F8EF8ABBD38DDDE9137DFEB3F1009927589041D06669E0E22FC2497A0C44C8DEA3488F525E67";
	char *pPrime2 = "CB9892EFC0060FC7C3EFC79BA7A37D60006EADEF15EBC7EE97647A5E91D012DE6091C29BBF80BEFF3640D5447EE66DD64F5E1C09B3889736F07D486D96BF34514235ABB2EA70F5C709009F3E2FF834A899EBA8DB98211ACD048CB133E238BEC3811CEBDC59A8830C0337942F2A6B4CE5D33403D71A960B1071CD5E25EC1F0529";
	char *pExponent1 = "9E6AE00C6556A5B22CBB0B9E5A39F2FE6EB3289D310439C32104775AB587CC1B568C7784573E91EDD3F08D05A7380CD3138C1AD310CC86925D04742082F02B811B297271F1B12E964F22C30E6A460AD60C5165B3581283CCC819FB4A5C7D37B3E9460CFEA9CD4B55BB6F90602BE0444695EC1FD6DBA6B2D885E9C2305F8C3EEF";
	char *pExponent2 = "87BB0C9FD5595FDA829FDA67C517A8EAAAF473F4B947DA9F0F985194613561E995B681BD2A55D4AA242B38D854999E8EDF9412B1225B0F79F5A8DAF3B9D4CD8B81791D21F1A0A3DA06006A297550231B1147C5E7BAC0BC88ADB320CD417B29D7AB689D3D911B020802250D74C6F23343E222AD3A11B95CB5A13394194814AE1B";
	char *pCoefficient = "7771B26191F90CA2F23559786933BE7DE6265BF549A20C0EB05FDA4418BC29417FF00FEDD301900861D58DF88220862F1D01B26B644D969611360464DE12BB6A32EEAECE9319793899F44D72374CB893B39B7ADD69668E3C13A656B7D5F4B7585F87A9B269F5074FB15795FF8C4B984BCFDF602C3FF1DC9C38C61C34BB025F19";

	char szPrivEncodeBuf[1024 * 2] = {0};
	char szPubEncodeBuf[1024 * 2] = {0};

	memset(&stRSAPrivKey, 0, sizeof(STRSAPrivateKey));
	memcpy(stRSAPrivKey.modulus, pModulus, strlen(pModulus));
	memcpy(stRSAPrivKey.publicExponent, pPublicExponent, strlen(pPublicExponent));
	memcpy(stRSAPrivKey.privateExponent, pPrivateExponent, strlen(pPrivateExponent));
	memcpy(stRSAPrivKey.prime1, pPrime1, strlen(pPrime1));
	memcpy(stRSAPrivKey.prime2, pPrime2, strlen(pPrime2));
	memcpy(stRSAPrivKey.exponent1, pExponent1, strlen(pExponent1));
	memcpy(stRSAPrivKey.exponent2, pExponent2, strlen(pExponent2));
	memcpy(stRSAPrivKey.coefficient, pCoefficient, strlen(pCoefficient));

	generateRSAKey(&stRSAPrivKey, szPrivEncodeBuf, szPubEncodeBuf);

	return(0);
}