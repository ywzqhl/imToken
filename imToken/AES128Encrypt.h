//
//  AES123Encrypt.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/25.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AES128Encrypt : NSObject
@property (nonatomic, copy) NSString *cipherFinalDecrypt;
+ (NSMutableData*) encryptString: (NSString*)stringToEncrypt withKey: (NSString*) keyString iv:(NSData *)iv;
+ (NSString*) decryptData: (NSData*) data withKey: (NSString*) keyString iv:(NSData *)iv;
@end
