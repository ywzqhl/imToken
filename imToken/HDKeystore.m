//
//  HDKeystore.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import "HDKeystore.h"
#import "ETHMnemonic.h"
#import "NSString+SHA3.h"
#import <BTCKey.h>
#import <BTCKeychain.h>
#import <BTCData.h>
#import "ETHAES128.h"
#import "AES128CTR.h"
#import "libscrypt.h"
#import "AES128Encrypt.h"
@interface HDKeystore ()
@property (nonatomic, copy) NSString *password;
@property (nonatomic, copy) NSString *mnemonic;
@property (nonatomic, copy) NSString *path;
@property (nonatomic, strong) NSData *seedData;
@property (nonatomic, strong) BTCKeychain *keychain;
@property (nonatomic, copy) NSString *seedString;
@property (nonatomic, copy) NSString *privateKeyString;
@property (nonatomic, copy) NSString *ivSeedString; //seed nonce
@property (nonatomic, copy) NSString *ivRootPrivStr; //RootprivteKey nonce
@property (nonatomic, copy) NSString *ivHDPathPriv;
@property (nonatomic, copy) NSString *ivPriv; //私钥nonce
@property (nonatomic, strong) NSMutableString *derivedKeyStr; //derivedKey
@end


@implementation HDKeystore

- (instancetype)initWithPassword:(NSString *)password mnemonic:(NSString *)mnemonic path:(NSString *)path {
    self = [super init];
    if (self) {
        self.password = password;
        self.mnemonic = mnemonic;
        self.path = path;
        [self getAddress];
        [self writeKsJson];
    }
    return self;
}

- (NSString *)getAddress {
    if ([self.mnemonic isEqualToString:@""] || self.mnemonic == nil) {
        self.mnemonic = [ETHMnemonic generateMnemonicString:@128 language:@"english"];
        NSLog(@"Mnemonic: %@", _mnemonic);
    }
    self.seedString = [ETHMnemonic deterministicSeedStringFromMnemonicString:_mnemonic passphrase:@"" language:@"english"];
    self.seedData = [self.seedString dataFromHexString];
    self.keychain = [[BTCKeychain alloc] initWithSeed:self.seedData];
    /**
     * SHA-3 -------------keccak256
     */
    if ([_path isEqualToString:@""] || _path == nil) {
        _path = @"m/44'/60'/0'/0";
    }
    NSLog(@"pub: %@", BTCHexFromData([_keychain keyWithPath:_path].uncompressedPublicKey));
    
    NSString *publicKeyStr = [BTCHexFromData([_keychain keyWithPath:_path].uncompressedPublicKey) substringFromIndex:2];
    NSLog(@"publicStr: %@", publicKeyStr);
    
    //NSString *compressPubKey = [publicKeyStr substringToIndex:64];
    
    self.privateKeyString = BTCHexFromData([_keychain keyWithPath:_path].privateKey);
    NSLog(@"privateStr: %@", self.privateKeyString);
    
    NSString *tempPub = [BTCHexFromData([_keychain keyWithPath:_path].uncompressedPublicKey) substringFromIndex:2];
    
    NSString *addressData = [[[tempPub dataFromHexString] newSha3:256] substringFromIndex:24];
    NSLog(@"addressData: %@", addressData);
    
    self.address = [@"0x" stringByAppendingString:addressData].lowercaseString;
    NSLog(@"generateAddressStr: %@", self.address);
    [self writeKsJson];
    
    
    uint64_t num = 1 <<18;
    NSLog(@"%llu", num);
    unsigned char derivedkey[32];
    NSString *s = [self generateSalt256];
    const uint8_t *salt = [s dataFromHexString].bytes;
    libscrypt_scrypt([self.password dataUsingEncoding:NSUTF8StringEncoding].bytes, [self.password dataUsingEncoding:NSUTF8StringEncoding].length, salt, [s dataFromHexString].length, 262144 , 8, 1, derivedkey, 32);
    self.derivedKeyStr = [[NSMutableString alloc] init];//encoding
    for (int i = 0 ; i < 32 ; ++i)
    {
        [_derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
    }
    /**
     *  AES128-CTR加密
     */
    //seed加密
   
    
    /**
     * 解密
     */
//    NSString *decryptStr = [AES128Encrypt decryptData:aesdata withKey:derivedKeyStr iv:ivData];
//    NSLog(@"seedStr: %@", decryptStr);
    
    //NSLog(@"%@", BTCHexFromData([self AESIv]));
    
    return self.address;
    
}

- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password {
    
return @"";
}


- (void)writeKsJson {
    self.ivSeedString = BTCHexFromData([self AESIv]);
    NSMutableData *aesSeed = [AES128Encrypt encryptString:self.seedString withKey:_derivedKeyStr iv:[self.ivSeedString dataFromHexString]];
    self.ivRootPrivStr = BTCHexFromData([self AESIv]);
    NSMutableData *aesRootPriv = [AES128Encrypt encryptString:_keychain.extendedPrivateKey withKey:_derivedKeyStr iv:[self.ivRootPrivStr dataFromHexString]];
    self.ivHDPathPriv = BTCHexFromData([self AESIv]);
    NSMutableData *aesPath = [AES128Encrypt encryptString:@"m/44'/60'/0'" withKey:_derivedKeyStr iv:[self.ivHDPathPriv dataFromHexString]];
    self.ivPriv = BTCHexFromData([self AESIv]);
    NSMutableData *aesPriv = [AES128Encrypt encryptString:self.privateKeyString withKey:_derivedKeyStr iv:[self.ivPriv dataFromHexString]];
    NSDictionary *info = @{@"curve":@"secp256k1", @"purpose":@"sign"};
    NSDictionary *encHdPathPriv = @{@"encStr":BTCHexFromData(aesPath), @"nonce":self.ivHDPathPriv};
    NSDictionary *priv = @{@"key":aesPriv, @"nonce":self.ivPriv};
    NSDictionary *encPrivKeys = @{self.privateKeyString:priv};
    NSArray *addresses = @[self.privateKeyString];
    NSDictionary *m_0_0_0 = @{@"info":info, @"encHdPathPriv":encHdPathPriv, @"hdIndex":@10 ,@"encPrivKeys":encPrivKeys, @"addresses":addresses};
    NSDictionary *encSeed = @{@"encStr": BTCHexFromData(aesSeed), @"nonce": self.ivSeedString};
    NSDictionary *encHdRootPriv = @{@"encStr": BTCHexFromData(aesRootPriv), @"nonce":self.ivRootPrivStr};
    NSDictionary *ksData = @{@"m/0'/0'/0'": m_0_0_0};
    NSDictionary *bigDic = @{@"encSeed":encSeed, @"ksData":ksData, @"encHdRootPriv":encHdRootPriv};
    
    NSString *ksJsonString = [self returnJSONStringWithDictionary:bigDic];
    NSDate *currentDate = [NSDate date];//获取当前时间，日期
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"YYYY-MM-dd-hh-mm-ss-SS"];
    NSString *dateString = [dateFormatter stringFromDate:currentDate];
    NSString *jsonpath = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject]stringByAppendingPathComponent:[[@"HD-" stringByAppendingString:dateString] stringByAppendingString:self.address]];
    BOOL isSuccess = [ksJsonString writeToFile:jsonpath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"%@", isSuccess ? @"successful" : @"failed");
    
    
    NSArray *path = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [path objectAtIndex:0];
    NSString *fileDirectory = [documentsDirectory stringByAppendingPathComponent:[[@"HD-" stringByAppendingString:dateString] stringByAppendingString:self.address]];
    NSString *dicStr = [NSString stringWithContentsOfFile:fileDirectory encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"^^^^^^^^^^^^^^^^^^^^^%@", dicStr);
}

/**
 * generate Salt 一个64bit的盐
 */
- (NSString *)generateSalt256 {
    unsigned char salt[32];
    for (int i=0; i<32; i++) {
        salt[i] = (unsigned char)arc4random();
    }
    NSMutableString *hexString = [NSMutableString string];
    for (int i=0; i<sizeof(salt); i++)
    {
        [hexString appendFormat:@"%02x", salt[i]];
    }
    return hexString;
}

- (void)generateDerivedKey {
    
}
- (NSString *)returnJSONStringWithDictionary:(NSDictionary *)dictionary{
    NSString *jsonStr = @"{";
    NSArray * keys = [dictionary allKeys];
    for (NSString * key in keys) {
        jsonStr = [NSString stringWithFormat:@"%@\"%@\":\"%@\",",jsonStr,key,[dictionary objectForKey:key]];
    }
    jsonStr = [NSString stringWithFormat:@"%@%@",[jsonStr substringWithRange:NSMakeRange(0, jsonStr.length-1)],@"}"];
    return jsonStr;
}
/**
 *  generate Iv
 */
- (NSData *)AESIv {
    return [AES128CTR randomDataOfLength:kCCBlockSizeAES128];
}
@end
