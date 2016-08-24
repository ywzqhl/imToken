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

@interface V3Keystore ()
@property (nonatomic, copy) NSString *mac;
@property (nonatomic, copy) NSString *macStr;

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
    // Make derivedKeys!
    NSData* myPassData = [passwordkey dataFromHexString];
    NSData* salt = [self generateSalt256];
    // How many rounds to use so that it takes 0.1s ?
    int rounds = CCCalibratePBKDF(kCCPBKDF2, myPassData.length, salt.length, kCCPRFHmacAlgSHA256, 32, 100);
    // Open CommonKeyDerivation.h for help
    unsigned char derivedkey[32];
    CCKeyDerivationPBKDF(kCCPBKDF2, myPassData.bytes, (long)[myPassData bytes], salt.bytes, salt.length, kCCPRFHmacAlgSHA256, rounds, derivedkey, 32);
    NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
    for (int i = 0 ; i < 32 ; ++i)
    {
        [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
    }
    NSLog(@"derivedKeyStr: %@", derivedKeyStr);
    NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
    NSLog(@"halfDerivedKeyStr: %@", halfDerivedKeyStr);
    
    if(err) {
        NSLog(@"json解析失败：%@",err);
    }
    if (dic) {
        NSDictionary *cryptoDic = dic[@"crypto"];
        self.macStr = cryptoDic[@"mac"];
        NSLog(@"################%@", _macStr);
        NSString *ciphertext = cryptoDic[@"ciphertext"];
        NSLog(@"1111111111111111%@", ciphertext);
        NSString *s = [halfDerivedKeyStr stringByAppendingString:ciphertext];
        self.mac = [s sha3:256];
        //self.mac = @"aa1506bc40e4db4d155a85db8e8428d0be60e348a7b585c15cb8c121437bb1d7";
    }
    if ([_mac isEqualToString:_macStr]) {
        
        NSLog(@"XXXXXXXXXXXXXXXXXX%@", _macStr);
        //数据持久化
        NSString *filePath = [self dictionaryFilePath];
        NSDictionary *dic1 = @{@"ksJson": _ksJson};
        BOOL isSuccess = [dic1 writeToFile:filePath atomically:YES];
        NSLog(@"%@", isSuccess ? @"successful" : @"fail");
        return [dic[@"address"] stringByAppendingString:[@"  " stringByAppendingString:dic[@"id"]]];
        
    } else {
    
        return @"";
    }

}

//Data Persistent
- (NSString *)dictionaryFilePath {
    NSDate* dat = [NSDate dateWithTimeIntervalSinceNow:0];
    NSTimeInterval a=[dat timeIntervalSince1970];
    NSString *timeString = [NSString stringWithFormat:@"%.0f", a];
    self.walletId = timeString;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSLog(@"%@", documents);
    return [documents stringByAppendingPathComponent:self.walletId];
}

- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password {
return @"";
}
/**
 * generate PRN
 */
- (NSData*)generateSalt256 {
    unsigned char salt[32];
    for (int i=0; i<32; i++) {
        salt[i] = (unsigned char)arc4random();
    }
    return [NSData dataWithBytes:salt length:32];
}


- (NSString *)ksJsonFile {
    
    
return @"";
}

@end
