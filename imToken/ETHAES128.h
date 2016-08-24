//
//  ETHAES128.h
//  CocoapodsTest
//
//  Created by 刘鸿博 on 16/8/17.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>
@interface ETHAES128 : NSObject
+ (NSMutableData*) encryptString: (NSString*) stringToEncrypt withKey: (NSString*) keyString;
+ (NSString*) decryptData: (NSData*) data withKey: (NSString*) keyString;
@end
