//
//  Keystore.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import "V3Keystore.h"
#import "SingleTonPassVlaue.h"
#import "NSString+SHA3.h"
#import <CommonCrypto/CommonCrypto.h>
#import "libscrypt.h"
@interface V3Keystore ()
@property (nonatomic, copy) NSString *mac;     //导入V3的mac
@property (nonatomic, copy) NSString *macStr;

@property (nonatomic, copy) NSString *outmac;  //导出v3的mac
@property (nonatomic, copy) NSString *outmacStr;

@property (nonatomic, copy) NSString *outputWallerId;
@property (nonatomic, copy) NSString *address;
@property (nonatomic, copy) NSString *outputPassword;
@end


@implementation V3Keystore
- (instancetype)init {
    self = [super init];
    if (self) {
        
    }
    return self;
}

-(instancetype)initWithPassword:(NSString *)password ksJson:(NSString *)ksJson {
    self = [super init];
    if (self) {
        self.password = password;
        self.ksJson = ksJson;
        [self getAddress];
    }
    return self;
}

- (instancetype)initWithWalletId:(NSString *)walletId address:(NSString *)address password:(NSString *)password {
    self = [super init];
    if (self) {
        self.outputWallerId = walletId;
        self.address = address;
        self.outputPassword = password;
        [self ksJsonFile];
    }
    return self;
}


- (NSString *)getAddress {
    NSData *jsonData = [_ksJson dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers
                                                          error:&err];
    
    NSString *passwordkey = self.password;
    if(err) {
        NSLog(@"json解析失败：%@",err);
    }

    if (dic) {
        NSDictionary *cryptoDic = dic[@"crypto"];
        NSString *kdf = cryptoDic[@"kdf"];
        if ([kdf isEqualToString:@"scrypt"]) {
            NSDictionary *kdfparams = cryptoDic[@"kdfparams"];
            NSString *ciphertext = cryptoDic[@"ciphertext"];
            NSString *s = kdfparams[@"salt"];
            NSString *n = kdfparams[@"n"];
            NSString *r = kdfparams[@"r"];
            NSString *p = kdfparams[@"p"];
            /**
             *   scrypt
             */
            unsigned char derivedkey[32];
            const uint8_t *salt = [s dataFromHexString].bytes;
            libscrypt_scrypt([passwordkey dataUsingEncoding:NSUTF8StringEncoding].bytes, [passwordkey dataUsingEncoding:NSUTF8StringEncoding].length, salt, [s dataFromHexString].length, [n intValue] , [r intValue], [p intValue], derivedkey, 32);
            NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
            for (int i = 0 ; i < 32 ; ++i)
            {
                [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
            }
            NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
            NSString *m = [halfDerivedKeyStr stringByAppendingString:ciphertext];
            self.mac = [[m dataFromHexString] newSha3:256];
            self.macStr = cryptoDic[@"mac"];
        } else{
            //解析Json得到salt
            NSDictionary *kdfparams = cryptoDic[@"kdfparams"];
            NSString *s = kdfparams[@"salt"];
            //解析Json得到round
            NSString *round = kdfparams[@"n"];
            const uint8_t *salt = [s dataFromHexString].bytes;
            unsigned char derivedkey[32];
            CCKeyDerivationPBKDF(kCCPBKDF2, [passwordkey dataUsingEncoding:NSUTF8StringEncoding].bytes, [passwordkey dataUsingEncoding:NSUTF8StringEncoding].length, salt, [s dataFromHexString].length, kCCPRFHmacAlgSHA256, [round intValue], derivedkey, 32);
            NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
            for (int i = 0 ; i < 32 ; ++i)
            {
                [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
            }
            NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
            if (dic) {
                NSDictionary *cryptoDic = dic[@"crypto"];
                self.macStr = cryptoDic[@"mac"];
                NSString *ciphertext = cryptoDic[@"ciphertext"];
                NSString *m = [halfDerivedKeyStr stringByAppendingString:ciphertext];
                self.mac = [m sha3:256];
              }        // Make derivedKeys!
          }
    }
        if ([_mac.lowercaseString isEqualToString:_macStr.lowercaseString]) {
            NSDate *currentDate = [NSDate date];//获取当前时间，日期
            NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
            [dateFormatter setDateFormat:@"YYYY-MM-dd-hh-mm-ss-SS"];
            NSString *dateString = [dateFormatter stringFromDate:currentDate];
            NSLog(@"dateString:%@",dateString);
        //数据持久化
            NSString * jsonpath = [NSHomeDirectory()stringByAppendingPathComponent:[[@"V3-" stringByAppendingString:dateString] stringByAppendingString:dic[@"-address"]]];
            NSString *kJ = _ksJson;
           BOOL isSuccess = [kJ writeToFile:jsonpath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"%@", isSuccess ? @"successful" : @"fail");
        return dic[@"address"];
        
    } else {
    
        return @"";
    }

}

- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password {
    
return @"";
    
}




- (NSString *)ksJsonFile {
    
    NSString *read = [[NSString alloc] initWithContentsOfFile:[NSHomeDirectory()stringByAppendingPathComponent:self.outputWallerId] encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"字典数据： %@", read);
    NSData *jsonData = [read dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers error:&err];
    
    if (dic) {
        NSDictionary *cryptoDic = dic[@"crypto"];
        NSString *kdf = cryptoDic[@"kdf"];
        if ([kdf isEqualToString:@"scrypt"]) {
            NSDictionary *kdfparams = cryptoDic[@"kdfparams"];
            NSString *s = kdfparams[@"salt"];
            NSString *n = kdfparams[@"n"];
            NSString *r = kdfparams[@"r"];
            NSString *p = kdfparams[@"p"];
            
            uint64_t num = 1 <<18;
            NSLog(@"%llu", num);
            unsigned char derivedkey[32];
            const uint8_t *salt = [s dataFromHexString].bytes;
            libscrypt_scrypt([self.outputPassword dataUsingEncoding:NSUTF8StringEncoding].bytes, [self.outputPassword dataUsingEncoding:NSUTF8StringEncoding].length, salt, [s dataFromHexString].length, 262144 , 8, 1, derivedkey, 32);
            NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
            for (int i = 0 ; i < 32 ; ++i)
            {
                [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
            }
            NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
            NSString *m = [halfDerivedKeyStr stringByAppendingString:@"bab660cd77814f69a84608cf05a3d00983d8c79eeeaa5f2d3ce47df0cbc8340b"];
            NSString *mac = [[m dataFromHexString] newSha3:256];
            NSLog(@"mac: %@", mac.lowercaseString);
            }        // Make derivedKeys!
        } else {
            
            NSDictionary *cryptoDic = dic[@"cryptoDic"];
            NSDictionary *kdfparams = cryptoDic[@"kdfparams"];
            NSString *s = kdfparams[@"salt"];
            //解析Json得到round
            NSString *round = kdfparams[@"n"];
            const uint8_t *salt = [s dataFromHexString].bytes;
            unsigned char derivedkey[32];
            CCKeyDerivationPBKDF(kCCPBKDF2, [self.outputPassword dataUsingEncoding:NSUTF8StringEncoding].bytes, [self.outputPassword dataUsingEncoding:NSUTF8StringEncoding].length, salt, [s dataFromHexString].length, kCCPRFHmacAlgSHA256, [round intValue], derivedkey, 32);
            NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
            for (int i = 0 ; i < 32 ; ++i)
            {
                [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
            }
            NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
            if (dic) {
                NSDictionary *cryptoDic = dic[@"crypto"];
                self.outmacStr = cryptoDic[@"mac"];
                NSString *ciphertext = cryptoDic[@"ciphertext"];
                NSString *m = [halfDerivedKeyStr stringByAppendingString:ciphertext];
                self.mac = [[m dataFromHexString] newSha3:256];
        }
    }
    
    if ([self.address isEqualToString:dic[@"address"] ] && [self.outmac.lowercaseString isEqualToString:self.outmacStr.lowercaseString]) {
        return read;
    } else {
    
        return @"错误";
    }
}
@end
