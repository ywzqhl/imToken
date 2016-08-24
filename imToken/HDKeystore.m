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
@interface HDKeystore ()
@property (nonatomic, copy) NSString *password;
@property (nonatomic, copy) NSString *mnemonic;
@property (nonatomic, copy) NSString *path;
@property (nonatomic, strong) NSData *seedData;
@property (nonatomic, strong) BTCKeychain *keychain;
@end


@implementation HDKeystore

- (instancetype)init {
    self = [super init];
    if (self) {
        [self dateForWalletId];
    }
    return self;
}
- (instancetype)initWithPassword:(NSString *)password mnemonic:(NSString *)mnemonic path:(NSString *)path {
    self = [super init];
    if (self) {
        self.password = password;
        self.mnemonic = mnemonic;
        self.path = path;
        [self getAddress];
    }
    return self;
}

- (NSString *)getAddress {
    if ([_mnemonic isEqualToString:@""] || _mnemonic == nil) {
        self.mnemonic = [ETHMnemonic generateMnemonicString:@128 language:@"english"];
        NSLog(@"Mnemonic: %@", _mnemonic);
    }
    NSString *seed = [ETHMnemonic deterministicSeedStringFromMnemonicString:_mnemonic passphrase:@"" language:@"english"];
    NSLog(@"seed: %@", seed);
    self.seedData = [seed dataFromHexString];
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
    
    NSString *privateKeyStr = BTCHexFromData([_keychain keyWithPath:_path].privateKey);
    NSLog(@"privateStr: %@", privateKeyStr);
    
    NSString *addressData = [[[_keychain keyWithPath:_path].uncompressedPublicKey newSha3:256] substringFromIndex:24];
    NSLog(@"addressData: %@", addressData);
    
    NSString *generateAddressStr = [@"0x" stringByAppendingString:addressData];
    NSLog(@"generateAddressStr: %@", generateAddressStr);
    return generateAddressStr;
}

- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password {
    
return @"";
}


- (void)dateForWalletId {
    NSDate* dat = [NSDate dateWithTimeIntervalSinceNow:0];
    NSTimeInterval a=[dat timeIntervalSince1970];
    NSString *timeString = [NSString stringWithFormat:@"%.0f", a];
    self.walletId = timeString;
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

- (void)genertaeDerivedKey {
    NSString *passwordkey = self.password;
    // Make derivedKeys!
    NSData* myPassData = [passwordkey dataFromHexString];
    NSData* salt = [self generateSalt256];
    
    // How many rounds to use so that it takes 0.1s ?
    int rounds = CCCalibratePBKDF(kCCPBKDF2, myPassData.length, salt.length, kCCPRFHmacAlgSHA256, 32, 100);
    // Open CommonKeyDerivation.h for help
    unsigned char derivedkey[32];
    CCKeyDerivationPBKDF(kCCPBKDF2, myPassData.bytes, myPassData.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA256, rounds, derivedkey, 32);
    NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
    for (int i = 0 ; i < 32 ; ++i)
    {
        [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
    }
    NSLog(@"derivedKeyStr: %@", derivedKeyStr);
    NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
    NSLog(@"halfDerivedKeyStr: %@", halfDerivedKeyStr);
    
    NSString *macStr = [halfDerivedKeyStr stringByAppendingString:@""];
    NSString *mac = [macStr sha3:256];
    NSLog(@"mac :%@", mac);
    if ([_path isEqualToString:@""] || _path == nil) {
        _path = @"m/44'/60'/0'/0";
    }
    NSMutableData *mixEncryptPrv = [ETHAES128 encryptString: BTCHexFromData([_keychain keyWithPath:_path].privateKey) withKey:derivedKeyStr];
    NSString *s = [self.mnemonic stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSMutableData *mixEncryptMnemonic = [ETHAES128 encryptString:s withKey:derivedKeyStr];
    NSLog(@"mixEncrypt: %@", BTCHexFromData(mixEncryptPrv)); //128bit
    NSLog(@"mixEncrypt: %@", BTCHexFromData(mixEncryptMnemonic));
    
    
    /**
     * Data Persistent
     */
    NSString *filePath = [self dictionaryFilePath];
    NSLog(@"===================%@", filePath);
    NSDictionary *dic = @{@"privateKey": BTCHexFromData(mixEncryptPrv), @"mnemonic":BTCHexFromData(mixEncryptMnemonic)};
    BOOL isSuccess = [dic writeToFile:filePath atomically:YES];
    NSLog(@"%@", isSuccess ? @"successful" : @"fail");
    //[self dictionaryReadFromFile];
    
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

//字典读取文件
- (void)dictionaryReadFromFile {
    NSString *filePath = [self dictionaryFilePath];
    NSDictionary *dic = [NSDictionary dictionaryWithContentsOfFile:filePath];
    NSLog(@"privateKey :%@\n mnemonic: %@", dic[@"privateKey"], dic[@"mnemonic"]);
}
@end
