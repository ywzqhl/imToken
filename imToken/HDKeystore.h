//
//  HDKeystore.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KeyStoreProtocol.h"
@interface HDKeystore : NSObject<KeyStoreProtocol>
@property (nonatomic, copy) NSString *walletId;
@property (nonatomic, copy) NSString *defaultHdPathString;
@property (nonatomic, strong) NSDictionary *encHdRootPriv; //encStr: iv:
@property (nonatomic ,strong) NSDictionary *encSeed; //encStr: iv:
@property (nonatomic, copy) NSString *address;
@property (nonatomic, strong) NSDictionary *encHdPathPriv; //encStr: iv:
@property (nonatomic, strong) NSDictionary *encPrivKeys; //encStr: iv:

//@property (nonatomic, strong) NSDictionary *ksData;
/**
 * m/0'/0'/0'(Dic): //address:(array[20])
   encHdPathPriv(Dic): //encStr: iv:
 */
- (instancetype)initWithPassword:(NSString *)password mnemonic:(NSString *)mnemonic path:(NSString *)path;
- (instancetype)initWithWalletId:(NSString *)walletId address:(NSString *)address password:(NSString *)password;
- (NSString *)ksJsonFile;
@end
