//
//  SingleTonPassVlaue.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SingleTonPassVlaue : NSObject
//生成HD钱包，导入HD钱包
@property (nonatomic, copy) NSString *HDPassword;
@property (nonatomic, copy) NSString *HDMnemonic;
@property (nonatomic, copy) NSString *HDPath;
@property (nonatomic, copy) NSString *HDAddress;
@property (nonatomic, copy) NSString *HDInputId;
//导入V3钱包
@property (nonatomic, copy) NSString *V3Password;
@property (nonatomic, copy) NSString *InputKsJson;
@property (nonatomic, copy) NSString *V3Id;
@property (nonatomic, copy) NSString *V3InputAddress;
//导入明文私钥钱包
@property (nonatomic, copy) NSString *PWPassword;
@property (nonatomic, copy) NSString *privateKey;
@property (nonatomic, copy) NSString *address;
//导出为V3
@property (nonatomic, copy) NSString *V3Wallet;
@property (nonatomic, copy) NSString *V3OutputAddress;
@property (nonatomic, copy) NSString *V3OutoutPassword;
@property (nonatomic, copy) NSString *OutputKsJson;
//HD钱包导出助记词
@property (nonatomic, copy) NSString *HDOutputID;
@property (nonatomic, copy) NSString *HDOutputPassword;
@property (nonatomic, copy) NSString *HDOutputMnemonic;
//签名交易
@property (nonatomic, copy) NSString *signatureWalletId;
@property (nonatomic, copy) NSString *signatureAddress;
@property (nonatomic, copy) NSString *signaturePassword;
@property (nonatomic, copy) NSString *signatureTxObj;
@property (nonatomic, copy) NSString *signatureTx;
+ (SingleTonPassVlaue *)shareSingleton;;
@end
