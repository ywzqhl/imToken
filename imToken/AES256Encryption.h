//
//  AES256Encryption.h
//  CocoapodsTest
//
//  Created by 刘鸿博 on 16/8/16.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>

@class NSString;

@interface NSData (Encryption)

- (NSData *)AES256EncryptWithKey:(NSString *)key;   //加密

- (NSData *)AES256DecryptWithKey:(NSString *)key;   //解密

- (NSString *)newStringInBase64FromData;            //追加64编码

+ (NSString*)base64encode:(NSString*)str;           //同上64编码



@end

@interface AES256Encryption : NSObject



@end
