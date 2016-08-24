//
//  PrivatekeyWallet.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/23.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import "PrivatekeyWallet.h"
#import <BTCKey.h>
#import "NSString+SHA3.h"
#import <BTCData.h>
@implementation PrivatekeyWallet
- (instancetype)initWithPrivatekey:(NSString *)privatekey password:(NSString *)password {
    self = [super init];
    if (self) {
        self.privatekey = privatekey;
        self.password = password;
    }
    return self;
}

- (NSString *)getAddress {
    BTCKey *btckey = [[BTCKey alloc] initWithPrivateKey:[self.privatekey dataFromHexString]];
    NSString *addressData = [[btckey.uncompressedPublicKey newSha3:256] substringFromIndex:24];
    NSString *generateAddressStr = [@"0x" stringByAppendingString:addressData];
    NSLog(@"generateAddressStr: %@", generateAddressStr);;
    return generateAddressStr;
}

- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password {
return @"";
}
@end
