//
//  CryptoManager.m
//  Moonlight
//
//  Created by Diego Waxemberg on 10/14/14.
//  Copyright (c) 2014 Moonlight Stream. All rights reserved.
//

#import "CryptoManager.h"
#import "mkcert.h"
#import "Logger.h"

#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

@implementation CryptoManager
#define SHA1_HASH_LENGTH 20
#define SHA256_HASH_LENGTH 32
static NSData* key = nil;
static NSData* cert = nil;
static NSData* p12 = nil;

+ (void)invalidateCachedKeyPair {
    key = nil;
    cert = nil;
    p12 = nil;
}

+ (void)generateAndPersistKeyPairForce:(BOOL)force {
    @synchronized(self) {
        if (!force && [CryptoManager keyPairExists]) {
            return;
        }

        Log(LOG_I, @"Generating Certificate... ");
        CertKeyPair certKeyPair = generateCertKeyPair();

        NSData* certData = [CryptoManager getCertFromCertKeyPair:&certKeyPair];
        NSData* p12Data = [CryptoManager getP12FromCertKeyPair:&certKeyPair];
        NSData* keyData = [CryptoManager getKeyFromCertKeyPair:&certKeyPair];

        freeCertKeyPair(certKeyPair);

        [CryptoManager writeCryptoObject:@"client.crt" data:certData];
        [CryptoManager writeCryptoObject:@"client.p12" data:p12Data];
        [CryptoManager writeCryptoObject:@"client.key" data:keyData];

        cert = certData;
        p12 = p12Data;
        key = keyData;

        Log(LOG_I, @"Certificate created");
    }
}

- (NSData*) createAESKeyFromSaltSHA1:(NSData*)saltedPIN {
    return [[self SHA1HashData:saltedPIN] subdataWithRange:NSMakeRange(0, 16)];
}

- (NSData*) createAESKeyFromSaltSHA256:(NSData*)saltedPIN {
    return [[self SHA256HashData:saltedPIN] subdataWithRange:NSMakeRange(0, 16)];
}

- (NSData*) SHA1HashData:(NSData*)data {
    unsigned char sha1[SHA1_HASH_LENGTH];
    SHA1([data bytes], [data length], sha1);
    NSData* bytes = [NSData dataWithBytes:sha1 length:sizeof(sha1)];
    return bytes;
}

- (NSData*) SHA256HashData:(NSData*)data {
    unsigned char sha256[SHA256_HASH_LENGTH];
    SHA256([data bytes], [data length], sha256);
    NSData* bytes = [NSData dataWithBytes:sha256 length:sizeof(sha256)];
    return bytes;
}

- (NSData*) aesEncrypt:(NSData*)data withKey:(NSData*)key {
    EVP_CIPHER_CTX* cipher;
    int ciphertextLen;

    cipher = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(cipher, EVP_aes_128_ecb(), [key bytes], NULL);
    EVP_CIPHER_CTX_set_padding(cipher, 0);

    NSMutableData* ciphertext = [NSMutableData dataWithLength:[data length]];
    EVP_EncryptUpdate(cipher,
                      [ciphertext mutableBytes],
                      &ciphertextLen,
                      [data bytes],
                      (int)[data length]);
    assert(ciphertextLen == [ciphertext length]);

    EVP_CIPHER_CTX_free(cipher);
    
    return ciphertext;
}

- (NSData*) aesDecrypt:(NSData*)data withKey:(NSData*)key {
    EVP_CIPHER_CTX* cipher;
    int plaintextLen;

    cipher = EVP_CIPHER_CTX_new();

    EVP_DecryptInit(cipher, EVP_aes_128_ecb(), [key bytes], NULL);
    EVP_CIPHER_CTX_set_padding(cipher, 0);

    NSMutableData* plaintext = [NSMutableData dataWithLength:[data length]];
    EVP_DecryptUpdate(cipher,
                      [plaintext mutableBytes],
                      &plaintextLen,
                      [data bytes],
                      (int)[data length]);
    assert(plaintextLen == [plaintext length]);

    EVP_CIPHER_CTX_free(cipher);
    
    return plaintext;
}

+ (NSData*) pemToDer:(NSData*)pemCertBytes {
    X509* x509;
    
    BIO* bio = BIO_new_mem_buf([pemCertBytes bytes], (int)[pemCertBytes length]);
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    bio = BIO_new(BIO_s_mem());
    i2d_X509_bio(bio, x509);
    X509_free(x509);

    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    
    NSData* ret = [[NSData alloc] initWithBytes:mem->data length:mem->length];
    BIO_free(bio);
    
    return ret;
}

- (bool) verifySignature:(NSData *)data withSignature:(NSData*)signature andCert:(NSData*)cert {
    X509* x509;
    BIO* bio = BIO_new_mem_buf([cert bytes], (int)[cert length]);
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    
    BIO_free(bio);
    
    if (!x509) {
        Log(LOG_E, @"Unable to parse certificate in memory");
        return NULL;
    }
    
    EVP_PKEY* pubKey = X509_get_pubkey(x509);
    EVP_MD_CTX *mdctx = NULL;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubKey);
    EVP_DigestVerifyUpdate(mdctx, [data bytes], [data length]);
    int result = EVP_DigestVerifyFinal(mdctx, (unsigned char*)[signature bytes], [signature length]);
    
    X509_free(x509);
    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_destroy(mdctx);
    
    return result > 0;
}

- (NSData *)signData:(NSData *)data withKey:(NSData *)key {
    BIO* bio = BIO_new_mem_buf([key bytes], (int)[key length]);
    
    EVP_PKEY* pkey;
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    
    BIO_free(bio);
    
    if (!pkey) {
        Log(LOG_E, @"Unable to parse private key in memory!");
        return NULL;
    }
    
    EVP_MD_CTX *mdctx = NULL;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, [data bytes], [data length]);
    size_t slen;
    EVP_DigestSignFinal(mdctx, NULL, &slen);
    unsigned char* signature = malloc(slen);
    int result = EVP_DigestSignFinal(mdctx, signature, &slen);
    
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);
    
    if (result <= 0) {
        free(signature);
        return NULL;
    }
    
    NSData* signedData = [NSData dataWithBytes:signature length:slen];
    free(signature);
    
    return signedData;
}

// 客户端证书的存储目录。macOS 上不能用 ~/Documents：
// 该目录受 TCC「文稿文件夹」隐私保护，未授权时 writeToFile 会静默失败，
// 导致 keyPairExists 永远为 NO，每次串流启动都会重新生成客户端证书，
// 已配对的主机会因为客户端证书变更而拒绝串流（client not authorized）。
// ~/Library/Application Support 不受 TCC 限制，且本 app 的数据库、日志
// 均已在此目录下正常读写。
+ (NSString *)cryptoStorageDirectory {
#if TARGET_OS_TV
    return nil;
#else
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *base = paths.firstObject;
    if (base.length == 0) {
        return nil;
    }

    NSString *dir = [base stringByAppendingPathComponent:@"Moonlight"];
    NSError *dirError = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&dirError];
    if (dirError != nil) {
        Log(LOG_E, @"无法创建证书存储目录 %@: %@", dir, dirError.localizedDescription);
        return nil;
    }
    return dir;
#endif
}

+ (NSData*) readCryptoObject:(NSString*)item {
#if TARGET_OS_TV
    return [[NSUserDefaults standardUserDefaults] dataForKey:item];
#elif TARGET_OS_OSX
    NSString *dir = [self cryptoStorageDirectory];
    NSData *data = nil;
    if (dir != nil) {
        data = [NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:item]];
    }

    // 一次性迁移：旧版本把证书写在 ~/Documents（受 TCC 保护，写入经常静默
    // 失败）。老文件可读且新位置缺失时，搬家到 Application Support。
    if (data == nil) {
        NSArray *legacyPaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *legacyFile = [legacyPaths.firstObject stringByAppendingPathComponent:item];
        NSData *legacyData = [NSData dataWithContentsOfFile:legacyFile];
        if (legacyData.length > 0) {
            Log(LOG_I, @"从旧位置迁移证书文件 %@", item);
            data = legacyData;
            [self writeCryptoObject:item data:legacyData];
        }
    }
    return data;
#else
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    NSString *file = [documentsDirectory stringByAppendingPathComponent:item];
    return [NSData dataWithContentsOfFile:file];
#endif
}

+ (void) writeCryptoObject:(NSString*)item data:(NSData*)data {
#if TARGET_OS_TV
    [[NSUserDefaults standardUserDefaults] setObject:data forKey:item];
#elif TARGET_OS_OSX
    NSString *dir = [self cryptoStorageDirectory];
    if (dir == nil) {
        Log(LOG_E, @"证书存储目录不可用，无法写入 %@", item);
        return;
    }

    NSError *error = nil;
    if (![data writeToFile:[dir stringByAppendingPathComponent:item] options:NSDataWritingAtomic error:&error]) {
        // 写入失败绝不能静默：否则 keyPairExists 会读不到文件，串流启动时
        // 会重新生成客户端证书，导致已配对主机拒绝连接。
        Log(LOG_E, @"写入证书文件 %@ 失败: %@", item, error.localizedDescription);
    }
#else
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    NSString *file = [documentsDirectory stringByAppendingPathComponent:item];
    [data writeToFile:file atomically:YES];
#endif
}

+ (NSData*) readCertFromFile {
    if (cert == nil) {
        cert = [CryptoManager readCryptoObject:@"client.crt"];
    }
    return cert;
}

+ (NSData*) readP12FromFile {
    if (p12 == nil) {
        p12 = [CryptoManager readCryptoObject:@"client.p12"];
    }
    return p12;
}

+ (NSData*) readKeyFromFile {
    if (key == nil) {
        key = [CryptoManager readCryptoObject:@"client.key"];
    }
    return key;
}

+ (bool) keyPairExists {
    NSData *keyData = [CryptoManager readCryptoObject:@"client.key"];
    NSData *p12Data = [CryptoManager readCryptoObject:@"client.p12"];
    NSData *certData = [CryptoManager readCryptoObject:@"client.crt"];

    bool keyFileExists = (keyData != nil && keyData.length > 0);
    bool p12FileExists = (p12Data != nil && p12Data.length > 0);
    bool certFileExists = (certData != nil && certData.length > 0);
    
    return keyFileExists && p12FileExists && certFileExists;
}

+ (NSData *)getSignatureFromCert:(NSData *)cert {
    BIO* bio = BIO_new_mem_buf([cert bytes], (int)[cert length]);
    X509* x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!x509) {
        Log(LOG_E, @"Unable to parse certificate in memory!");
        return NULL;
    }
    
#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
    ASN1_BIT_STRING *asnSignature = x509->signature;
#elif (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ASN1_BIT_STRING *asnSignature;
    X509_get0_signature(&asnSignature, NULL, x509);
#else
    const ASN1_BIT_STRING *asnSignature;
    X509_get0_signature(&asnSignature, NULL, x509);
#endif
    
    NSData* sig = [NSData dataWithBytes:asnSignature->data length:asnSignature->length];
    
    X509_free(x509);
    
    return sig;
}

+ (NSData*)getKeyFromCertKeyPair:(CertKeyPair*)certKeyPair {
    BIO* bio = BIO_new(BIO_s_mem());
    
    PEM_write_bio_PrivateKey_traditional(bio, certKeyPair->pkey, NULL, NULL, 0, NULL, NULL);
    
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    NSData* data = [NSData dataWithBytes:mem->data length:mem->length];
    BIO_free(bio);
    return data;
}

+ (NSData*)getP12FromCertKeyPair:(CertKeyPair*)certKeyPair {
    BIO* bio = BIO_new(BIO_s_mem());
    
    i2d_PKCS12_bio(bio, certKeyPair->p12);
    
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    NSData* data = [NSData dataWithBytes:mem->data length:mem->length];
    BIO_free(bio);
    return data;
}

+ (NSData*)getCertFromCertKeyPair:(CertKeyPair*)certKeyPair {
    BIO* bio = BIO_new(BIO_s_mem());
    
    PEM_write_bio_X509(bio, certKeyPair->x509);
    
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    NSData* data = [NSData dataWithBytes:mem->data length:mem->length];
    BIO_free(bio);
    return data;
}

+ (void) generateKeyPairUsingSSL {
    [CryptoManager generateAndPersistKeyPairForce:NO];
}

+ (void)regenerateKeyPairUsingSSL {
    [CryptoManager invalidateCachedKeyPair];
    [CryptoManager generateAndPersistKeyPairForce:YES];
}

@end
