//
//  PBKDF2encrypted.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/23.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <openssl/evp.h>
const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
const NSUInteger kAlgorithmKeySize = kCCKeySizeAES128;
const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
@interface PBKDF2encrypted : NSObject

+ (NSData *)AESKeyForPassword:(NSString *)password
                         salt:(NSData *)salt;

+ (NSData *)encryptedDataForData:(NSData *)data
                        password:(NSString *)password
                              iv:(NSData **)iv
                            salt:(NSData **)salt
                           error:(NSError **)error;

+ (NSData *)decryptedDataForData:(NSData *)data
                        password:(NSString *)password
                              iv:(NSData **)iv
                            salt:(NSData **)salt
                           error:(NSError **)error;
@end
