//
//  AES128CTR.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/25.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AES128CTR : NSObject
//aes-128-ctr
+ (NSData *)encryptedDataForData:(NSData *)data
                        password:(NSString *)password
                              iv:(NSData *)iv
                            salt:(NSData *)salt
                           error:(NSError **)error;


+ (NSData *)randomDataOfLength:(size_t)length;
+ (NSData *)AESKeyForPassword:(NSString *)password
                         salt:(NSData *)salt;
@end
