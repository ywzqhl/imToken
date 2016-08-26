//
//  ReactNativeAPI.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/20.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//
#import "ReactNativeAPI.h"
#import "SingleTonPassVlaue.h"
#import "V3Keystore.h"
#import "HDKeystore.h"
#import "PrivatekeyWallet.h"
@implementation ReactNativeAPI
RCT_EXPORT_MODULE();
/**
 * 生成HD钱包，导入HD钱包
 generateWallet(password, mnemonic = ‘’, path=“m/44’/46’/0’”) return id, address
 */
RCT_EXPORT_METHOD(Password:(NSString *)password mnemonic:(NSString *)mnemonic path:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    
    HDKeystore *hdkeystore = [[HDKeystore alloc] initWithPassword:password mnemonic:mnemonic path:path];
    resolve(@{@"address": [hdkeystore getAddress]});
    
    
}

/**
 * 导入V3钱包
   importV3Wallet(password, ksJson) return id, address
 */
RCT_EXPORT_METHOD(V3Password:(NSString *)v3password ksJson:(NSString *)ksJson resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    V3Keystore *v3keyStore = [[V3Keystore alloc] initWithPassword:v3password ksJson:ksJson];
    resolve(@{@"address": [v3keyStore getAddress]});
}

/**
 * 导入明文私钥钱包
 importPrivateKeyWallet(password, privateKey) return, address
 */
RCT_EXPORT_METHOD(PWPassword:(NSString *)pwpassword privatekey:(NSString *)privatekey resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    PrivatekeyWallet *privatekeywallet = [[PrivatekeyWallet alloc] initWithPrivatekey:privatekey password:pwpassword];
    resolve(@{@"address": [privatekeywallet getAddress]});
}
/**
 * 导出为V3
 exportV3(walletId, address, password) return ksJson {
 
	if V3 {
	} else if HD {   ??????
	}
 }
 */
RCT_EXPORT_METHOD(V3WalletID:(NSString *)v3WalletID address:(NSString *)address password:(NSString *)password resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    if ([v3WalletID hasPrefix:@"V3"]) {
        V3Keystore *v3keystore = [[V3Keystore alloc] initWithWalletId:v3WalletID address:address password:password];
        
        resolve(@{@"ksJson":[v3keystore ksJsonFile]});
    } else if ([v3WalletID hasPrefix:@"HD"] ){
        HDKeystore *hdkeystore = [[HDKeystore alloc] initWithWalletId:v3WalletID address:address password:password];
        resolve(@{@"keJson":[hdkeystore ksJsonFile]});
    } else {
    
    }
    
    
    
}
/**
 * HD钱包导出助记词
 exportHDMnemonic(walletId, password) return mnemonic {
	if V3 {
 error
	} else if HD {
	}
 }
 */
RCT_EXPORT_METHOD(HDWalletID:(NSString *)hdWalletID password:(NSString *)password mnemonic:(NSString *)mnemonic resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    
    
}
/**
 * 签名交易
 signTx(walletId, address, password, txObj) return signedTx {
	if V3 {
	} else if HD {
	}
 }
 */
RCT_EXPORT_METHOD(SignatureWalletID:(NSString *)signayureWalletID address:(NSString *)address password:(NSString *)password txObj:(NSString *)txObj signTx:(NSString *)signTx resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
   
    
}
@end
