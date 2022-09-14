/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "FactoryDataProvider.h"
#include "CHIPDevicePlatformConfig.h"
#include <platform/CHIPDeviceConfig.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/logging/CHIPLogging.h>
#include <lib/support/Base64.h>

#include "qvCHIP.h"

#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID != 0xFFF1

// Using generated data blobs
extern const uint8_t qorvo_cd_bin[];
extern const unsigned int qorvo_cd_bin_len;

extern const uint8_t qorvo_dac_cert_1_der[];
extern const unsigned int qorvo_dac_cert_1_der_len;
#define qorvo_dac_cert_der qorvo_dac_cert_1_der
#define qorvo_dac_cert_der_len qorvo_dac_cert_1_der_len

extern const uint8_t qorvo_dac_publ_key_1_der[];
extern const unsigned int qorvo_dac_publ_key_1_der_len;
#define qorvo_dac_publ_key_der qorvo_dac_publ_key_1_der
#define qorvo_dac_publ_key_der_len qorvo_dac_publ_key_1_der_len

extern const uint8_t qorvo_dac_priv_key_1_der[];
extern const unsigned int qorvo_dac_priv_key_1_der_len;
#define qorvo_dac_priv_key_der qorvo_dac_priv_key_1_der
#define qorvo_dac_priv_key_der_len qorvo_dac_priv_key_1_der_len

extern const uint8_t qorvo_pai_cert_der[];
extern const unsigned int qorvo_pai_cert_der_len;
#endif

// NOTE! This key is for test/certification only and should not be available in production devices!
// If CONFIG_CHIP_FACTORY_DATA is enabled, this value is read from the factory data.
#ifndef CHIP_DEVICE_CONFIG_TEST_EVENT_TRIGGER_ENABLE_KEY
#define CHIP_DEVICE_CONFIG_TEST_EVENT_TRIGGER_ENABLE_KEY { \
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, \
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  \
}
#endif //CHIP_DEVICE_CONFIG_TEST_EVENT_TRIGGER_ENABLE_KEY

namespace chip {
namespace {

#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID != 0xFFF1
CHIP_ERROR LoadKeypairFromRaw(ByteSpan privateKey, ByteSpan publicKey, Crypto::P256Keypair & keypair)
{
    Crypto::P256SerializedKeypair serializedKeypair;
    ReturnErrorOnFailure(serializedKeypair.SetLength(privateKey.size() + publicKey.size()));
    memcpy(serializedKeypair.Bytes(), publicKey.data(), publicKey.size());
    memcpy(serializedKeypair.Bytes() + publicKey.size(), privateKey.data(), privateKey.size());
    return keypair.Deserialize(serializedKeypair);
}
#endif //#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1

} // namespace

namespace DeviceLayer {


CHIP_ERROR FactoryDataProvider::Init()
{
    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetCertificationDeclaration(MutableByteSpan & outBuffer)
{
#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
    // Example Provider should be used
    return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
#else
    // qvCHIP_FactoryDataGetValue();

    return CopySpanToMutableSpan(ByteSpan(qorvo_cd_bin, qorvo_cd_bin_len), outBuffer);
#endif //CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
}


CHIP_ERROR FactoryDataProvider::GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer)
{
    out_firmware_info_buffer.reduce_size(0);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetDeviceAttestationCert(MutableByteSpan & outBuffer)
{
#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
    // Example Provider should be used
    return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
#else
    // qvCHIP_FactoryDataGetValue();

    // ReturnErrorCodeIf(outBuffer.size() < readLength, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != success, CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(outBuffer.data(), mFactoryData.dac_cert.data, readLength);
    // outBuffer.reduce_size(readLength);

    return CopySpanToMutableSpan(ByteSpan(qorvo_dac_cert_der,qorvo_dac_cert_der_len), outBuffer);
#endif //CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
}


CHIP_ERROR FactoryDataProvider::GetProductAttestationIntermediateCert(MutableByteSpan & outBuffer)
{
#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
    // Example Provider should be used
    return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
#else
    // qvCHIP_FactoryDataGetValue();
    
    // ReturnErrorCodeIf(outBuffer.size() < readLength, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != success, CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(outBuffer.data(), mFactoryData.pai_cert.data, readLength);
    // outBuffer.reduce_size(readLength);

    return CopySpanToMutableSpan(ByteSpan(qorvo_pai_cert_der, qorvo_pai_cert_der_len), outBuffer);
#endif //CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
}


CHIP_ERROR FactoryDataProvider::SignWithDeviceAttestationKey(const ByteSpan & messageToSign,
                                                             MutableByteSpan & outSignBuffer)
{
#if CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID == 0xFFF1
    // Example Provider should be used
    return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
#else
    // qvCHIP_FactoryDataGetValue(dac_private_key);
    // qvCHIP_FactoryDataGetValue(dac_public_key);

    Crypto::P256ECDSASignature signature;
    Crypto::P256Keypair keypair;

    VerifyOrReturnError(IsSpanUsable(outSignBuffer), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(IsSpanUsable(messageToSign), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(outSignBuffer.size() >= signature.Capacity(), CHIP_ERROR_BUFFER_TOO_SMALL);

    // In a non-exemplary implementation, the public key is not needed here. It is used here merely because
    // Crypto::P256Keypair is only (currently) constructable from raw keys if both private/public keys are present.
    ReturnErrorOnFailure(LoadKeypairFromRaw(ByteSpan(qorvo_dac_priv_key_der, qorvo_dac_priv_key_der_len), ByteSpan(qorvo_dac_publ_key_der, qorvo_dac_publ_key_der_len), keypair));
    // ReturnErrorOnFailure(LoadKeypairFromRaw(ByteSpan(qorvo_dac_priv_key_der_fff1, 32), ByteSpan(qorvo_dac_publ_key_der_fff1, 65), keypair));
    ReturnErrorOnFailure(keypair.ECDSA_sign_msg(messageToSign.data(), messageToSign.size(), signature));

    return CopySpanToMutableSpan(ByteSpan{ signature.ConstBytes(), signature.Length() }, outSignBuffer);
#endif
}


CHIP_ERROR FactoryDataProvider::GetSetupDiscriminator(uint16_t & setupDiscriminator)
{
    CHIP_ERROR err = CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;

    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 

#if defined(CHIP_DEVICE_CONFIG_USE_TEST_SETUP_DISCRIMINATOR) && CHIP_DEVICE_CONFIG_USE_TEST_SETUP_DISCRIMINATOR
    setupDiscriminator = CHIP_DEVICE_CONFIG_USE_TEST_SETUP_DISCRIMINATOR;
    err = CHIP_NO_ERROR;
#endif // defined(CHIP_DEVICE_CONFIG_USE_TEST_SETUP_DISCRIMINATOR) && CHIP_DEVICE_CONFIG_USE_TEST_SETUP_DISCRIMINATOR

    return err;
}


CHIP_ERROR FactoryDataProvider::SetSetupDiscriminator(uint16_t setupDiscriminator)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}


CHIP_ERROR FactoryDataProvider::GetSpake2pIterationCount(uint32_t & iterationCount)
{
    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 

    CHIP_ERROR err = CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;

#if defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_ITERATION_COUNT) && CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_ITERATION_COUNT
    iterationCount = CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_ITERATION_COUNT;
    err            = CHIP_NO_ERROR;
#endif // defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_ITERATION_COUNT) && CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_ITERATION_COUNT

    return err;
}


CHIP_ERROR FactoryDataProvider::GetSpake2pSalt(MutableByteSpan & saltBuf)
{
    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 

    // ReturnErrorCodeIf(saltBuf.size() < readLength, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(saltBuf.data(), mFactoryData.spake2_salt.data, readLengthn);
    // saltBuf.reduce_size(readLength);

    static constexpr size_t kSpake2pSalt_MaxBase64Len = BASE64_ENCODED_LEN(chip::Crypto::kSpake2p_Max_PBKDF_Salt_Length) + 1;

    CHIP_ERROR err                          = CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
    char saltB64[kSpake2pSalt_MaxBase64Len] = { 0 };
    size_t saltB64Len                       = 0;

#if defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_SALT)
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        saltB64Len = strlen(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_SALT);
        ReturnErrorCodeIf(saltB64Len > sizeof(saltB64), CHIP_ERROR_BUFFER_TOO_SMALL);
        memcpy(saltB64, CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_SALT, saltB64Len);
        err = CHIP_NO_ERROR;
    }
#endif // defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_SALT)

    ReturnErrorOnFailure(err);
    size_t saltLen = chip::Base64Decode32(saltB64, saltB64Len, reinterpret_cast<uint8_t *>(saltB64));

    ReturnErrorCodeIf(saltLen > saltBuf.size(), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(saltBuf.data(), saltB64, saltLen);
    saltBuf.reduce_size(saltLen);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetSpake2pVerifier(MutableByteSpan & verifierBuf, size_t & verifierLen)
{
    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 

    // ReturnErrorCodeIf(verifierBuf.size() < readLength, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != , CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(verifierBuf.data(), mFactoryData.spake2_verifier.data, mFactoryData.spake2_verifier.len);
    // verifierLen = readLength;
    // verifierBuf.reduce_size(verifierLen);

    static constexpr size_t kSpake2pSerializedVerifier_MaxBase64Len =
        BASE64_ENCODED_LEN(chip::Crypto::kSpake2p_VerifierSerialized_Length) + 1;

    ChipError err = CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
    char verifierB64[kSpake2pSerializedVerifier_MaxBase64Len] = { 0 };
    size_t verifierB64Len                                     = 0;

    // Lookup in actual HW implementation

#if defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER)
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        verifierB64Len = strlen(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER);
        ReturnErrorCodeIf(verifierB64Len > sizeof(verifierB64), CHIP_ERROR_BUFFER_TOO_SMALL);
        memcpy(verifierB64, CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER, verifierB64Len);
        err = CHIP_NO_ERROR;
    }
#endif // defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER)

    ReturnErrorOnFailure(err);
    verifierLen = chip::Base64Decode32(verifierB64, verifierB64Len, reinterpret_cast<uint8_t *>(verifierB64));
    ReturnErrorCodeIf(verifierLen > verifierBuf.size(), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(verifierBuf.data(), verifierB64, verifierLen);
    verifierBuf.reduce_size(verifierLen);

    return err;


#if defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER)
    verifierB64Len = strlen(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER);
    ReturnErrorCodeIf(verifierB64Len > sizeof(verifierB64), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(verifierB64, CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER, verifierB64Len);
    err = CHIP_NO_ERROR;    
#endif // defined(CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER)

    return err;
}


CHIP_ERROR FactoryDataProvider::GetSetupPasscode(uint32_t & setupPasscode)
{
    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 
    // ReturnErrorCodeIf(result != , CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);
    // setupPasscode = ;

    ChipError err = CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;

#if defined(CHIP_DEVICE_CONFIG_USE_TEST_SETUP_PIN_CODE) && CHIP_DEVICE_CONFIG_USE_TEST_SETUP_PIN_CODE
    setupPasscode = CHIP_DEVICE_CONFIG_USE_TEST_SETUP_PIN_CODE;
    err           = CHIP_NO_ERROR;
#endif // defined(CHIP_DEVICE_CONFIG_USE_TEST_SETUP_PIN_CODE) && CHIP_DEVICE_CONFIG_USE_TEST_SETUP_PIN_CODE

    return err;
}


CHIP_ERROR FactoryDataProvider::SetSetupPasscode(uint32_t setupPasscode)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}


CHIP_ERROR FactoryDataProvider::GetVendorName(char * buf, size_t bufSize)
{
    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 

    // ReturnErrorCodeIf(bufSize < readLength + 1, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != , CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(buf, mFactoryData.vendor_name.data, readLength);
    // buf[readLength] = 0;

    ReturnErrorCodeIf(bufSize < sizeof(CHIP_DEVICE_CONFIG_DEVICE_VENDOR_NAME), CHIP_ERROR_BUFFER_TOO_SMALL);
    strcpy(buf, CHIP_DEVICE_CONFIG_DEVICE_VENDOR_NAME);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetVendorId(uint16_t & vendorId)
{
    // qvCHIP_FactoryDataGetValue(&vendorId);
    // if (result = ...)
    // 
    // VerifyOrReturnError(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    vendorId = static_cast<uint16_t>(CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetProductName(char * buf, size_t bufSize)
{
    // qvCHIP_FactoryDataGetValue();
    // if (result = ...)
    // 
    // ReturnErrorCodeIf(bufSize < readLength + 1, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);


    // memcpy(buf, mFactoryData.product_name.data, readLength);
    // buf[readLength] = 0;

    ReturnErrorCodeIf(bufSize < sizeof(CHIP_DEVICE_CONFIG_DEVICE_PRODUCT_NAME), CHIP_ERROR_BUFFER_TOO_SMALL);
    strcpy(buf, CHIP_DEVICE_CONFIG_DEVICE_PRODUCT_NAME);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetProductId(uint16_t & productId)
{
    // qvCHIP_FactoryDataGetValue(& productId);
    // if (result = ...)
    // 

    // VerifyOrReturnError(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    productId = static_cast<uint16_t>(CHIP_DEVICE_CONFIG_DEVICE_PRODUCT_ID);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetSerialNumber(char * buf, size_t bufSize)
{
    // qvCHIP_FactoryDataGetValue(& productId);
    // if (result = ...)
    // 

    // ReturnErrorCodeIf(bufSize < readLength + 1, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(buf, ..., readLength);
    // buf[readLength] = 0;

    ChipError err = CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
    size_t serialNumLen = 0; // without counting null-terminator
    
#ifdef CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER
    if (CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER[0] != 0 && err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        ReturnErrorCodeIf(sizeof(CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER) > bufSize, CHIP_ERROR_BUFFER_TOO_SMALL);
        memcpy(buf, CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER, sizeof(CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER));
        serialNumLen = sizeof(CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER) - 1;
        err = CHIP_NO_ERROR;
    }
#endif // CHIP_DEVICE_CONFIG_TEST_SERIAL_NUMBER

    ReturnErrorCodeIf(serialNumLen >= bufSize, CHIP_ERROR_BUFFER_TOO_SMALL);
    ReturnErrorCodeIf(buf[serialNumLen] != 0, CHIP_ERROR_INVALID_STRING_LENGTH);

    return err;
}


CHIP_ERROR FactoryDataProvider::GetManufacturingDate(uint16_t & year, uint8_t & month, uint8_t & day)
{
    // qvCHIP_FactoryDataGetValue(& ... );
    // if (result = ...)
    // 
    // VerifyOrReturnError(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // year  = ;
    // month = ;
    // day   = ;
    
    //return CHIP_NO_ERROR;

    return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
}


CHIP_ERROR FactoryDataProvider::GetHardwareVersion(uint16_t & hardwareVersion)
{
    // qvCHIP_FactoryDataGetValue(& hardwareVersion);
    // if (result = ...)
    // 
    // VerifyOrReturnError(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    hardwareVersion = static_cast<uint16_t>(CHIP_DEVICE_CONFIG_DEFAULT_DEVICE_HARDWARE_VERSION);
    
    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetHardwareVersionString(char * buf, size_t bufSize)
{
    // qvCHIP_FactoryDataGetValue(& hardwareVersion);
    // if (result = ...)
    // 

    // ReturnErrorCodeIf(bufSize < readLength + 1, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(buf, ..., readLength);
    // buf[readLength] = 0;

    ReturnErrorCodeIf(bufSize < sizeof(CHIP_DEVICE_CONFIG_DEFAULT_DEVICE_HARDWARE_VERSION_STRING), CHIP_ERROR_BUFFER_TOO_SMALL);
    strcpy(buf, CHIP_DEVICE_CONFIG_DEFAULT_DEVICE_HARDWARE_VERSION_STRING);

    return CHIP_NO_ERROR;
}


CHIP_ERROR FactoryDataProvider::GetRotatingDeviceIdUniqueId(MutableByteSpan & uniqueIdSpan)
{
    // qvCHIP_FactoryDataGetValue(& hardwareVersion);
    // if (result = ...)
    // 

    // ReturnErrorCodeIf(uniqueIdSpan.size() < readLength, CHIP_ERROR_BUFFER_TOO_SMALL);
    // ReturnErrorCodeIf(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

    // memcpy(uniqueIdSpan.data(), mFactoryData.rd_uid.data, readLength);

    //return CHIP_NO_ERROR;
    return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
}


CHIP_ERROR FactoryDataProvider::GetEnableKey(MutableByteSpan & enableKey)
{
    // qvCHIP_FactoryDataGetValue(& hardwareVersion);
    // if (result = ...)
    // 
    // ReturnErrorCodeIf(result != ..., CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);
    // ReturnErrorCodeIf(enableKey.size() < readLength, CHIP_ERROR_BUFFER_TOO_SMALL);

    // memcpy(enableKey.data(), ..., readLength);

    // enableKey.reduce_size(readLength);

    constexpr uint8_t kTesteventTriggerEnableKey[] = CHIP_DEVICE_CONFIG_TEST_EVENT_TRIGGER_ENABLE_KEY;

    memcpy(enableKey.data(), kTesteventTriggerEnableKey, sizeof(kTesteventTriggerEnableKey));

    return CHIP_NO_ERROR;
}

} // namespace DeviceLayer
} // namespace chip
