//
//  PBKDF2encrypted.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/23.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import "PBKDF2encrypted.h"

@implementation PBKDF2encrypted
+ (NSData *)AESKeyForPassword:(NSString *)password
                         salt:(NSData *)salt {
    NSMutableData *
    derivedKey = [NSMutableData dataWithLength:kAlgorithmKeySize];
    int result = PKCS5_PBKDF2_HMAC_SHA1(password.UTF8String, (int)[password length],
                                        salt.bytes, (int)[salt length], 10000,
                                        (int)[derivedKey length], derivedKey.mutableBytes);
    NSAssert(result == 1,
             @"Unable to create AES key for password: %d", result);
    
    return derivedKey;
}
+ (NSData *)encryptedDataForData:(NSData *)data
                        password:(NSString *)password
                              iv:(NSData **)iv
                            salt:(NSData **)salt
                           error:(NSError **)error {
    
    NSData *key = [self AESKeyForPassword:password salt:*salt];
    
    size_t outLength;
    NSMutableData *
    cipherData = [NSMutableData dataWithLength:data.length +
                  kAlgorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     kAlgorithm, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     (*iv).bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"error"
                                         code:result
                                     userInfo:nil];
        }
        return nil;
    }
    
    return cipherData;
}

+ (NSData *)decryptedDataForData:(NSData *)data
                        password:(NSString *)password
                              iv:(NSData **)iv
                            salt:(NSData **)salt
                           error:(NSError **)error {
    
    NSData *key = [self AESKeyForPassword:password salt:*salt];
    
    size_t outLength;
    NSMutableData *
    cipherData = [NSMutableData dataWithLength:data.length +
                  kAlgorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt,
                     kAlgorithm,
                     kCCOptionPKCS7Padding,
                     key.bytes,
                     key.length,
                     (*iv).bytes ,
                     data.bytes,
                     data.length,
                     cipherData.mutableBytes,
                     cipherData.length,
                     &outLength);
    
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"error"
                                         code:result
                                     userInfo:nil];
        }
        return nil;
    }
    
    return cipherData;
}
@end
