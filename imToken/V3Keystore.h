//
//  Keystore.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KeyStoreProtocol.h"
@interface V3Keystore : NSObject<KeyStoreProtocol>
@property (nonatomic, copy) NSString *walletId;
@property (nonatomic, copy) NSString *ksJson;
@property (nonatomic, copy) NSString *password;
//- (NSString *)getAddress;
//- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password;
- (instancetype)initWithPassword:(NSString *)password ksJson:(NSString *)ksJson;
- (instancetype)initWithWalletId:(NSString *)walletId address:(NSString *)address password:(NSString *)password;
- (NSString *)ksJsonFile;
@end
