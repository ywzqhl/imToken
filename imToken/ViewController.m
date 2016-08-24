//
//  ViewController.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/19.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import "ViewController.h"
#import <BTCMnemonic.h>
#import <BTCData.h>
#import "ETHMnemonic.h"
#import <BTCKeychain.h>
#import <BTCKey.h>
#import <BTCAddress.h>
#import "AES256Encryption.h"
#import <NSData+BTCData.h>
#import <BTCEncryptedBackup.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>
#import "ETHAES128.h"
#import "NSString+SHA3.h"
#import <BTCMnemonic.h>
#import "SingleTonPassVlaue.h"
#import "V3Keystore.h"
#import "ReactNativeAPI.h"
@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *walletName;
@property (weak, nonatomic) IBOutlet UITextField *walletPassword;
@property (nonatomic, strong) BTCMnemonic *mnenoic; //助记词类
@property (nonatomic, copy) NSString *mnemonic; //助记词
@property (nonatomic, strong) NSData *seedData;
@property (nonatomic, strong) BTCKeychain *keychain;
@end

@implementation ViewController

- (NSData *)seedData {
    if (!_seedData) {
        self.seedData = [[NSData alloc] init];
    }
    return _seedData;
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
/**
 * generate 128bit random number
 */
- (NSData *)random128Bit {
    unsigned char buf[16];
    arc4random_buf(buf, sizeof(buf));
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}
- (void)viewDidLoad {
    [super viewDidLoad];
    [self date];
    //[self analysisKsJson];
    // Do any additional setup after loading the view, typically from a nib.
     NSString *ksJson = @"{\"address\":\"b5a2bab38103c45f6b918b9db83d7466375da60a\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"c08d5969ddf4c70e96a4de5e68f45ea682cee0147a8a1b64f989509f3a3b1096\",\"cipherparams\":{\"iv\":\"5447d7b105760d33a6b167eff84f9857\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"e32c6e32c4d313c3ae6fd40281d8ac0550865b0f163983d6b6ca21e171a979e1\"},\"mac\":\"aa1506bc40e4db4d155a85db8e8428d0be60e348a7b585c15cb8c121437bb1d7\"},\"id\":\"21094d2e-5c0a-41b6-8435-a9580e2a4c63\",\"version\":3}";
    V3Keystore *v = [[V3Keystore alloc] initWithPassword:@"111111" ksJson:ksJson];
    NSLog(@"&&&&&&&&&&&&&&&&&&&&&&&&&%@", [v getAddress]);
}
- (IBAction)createWallet:(id)sender {
    
    /**
     * CoreBitCoin Fouction
     */
    // Generating a mnemonic
    
    
    /**
     * Mnemonic list / local file
     */
    self.mnemonic = [ETHMnemonic generateMnemonicString:@128 language:@"english"];
    NSLog(@"Mnemonic: %@", _mnemonic);
    UIAlertView *alertview = [[UIAlertView alloc] initWithTitle:@"请记住以下词汇" message:_mnemonic delegate:self cancelButtonTitle:@"取消" otherButtonTitles:@"确定", nil];
    [alertview show];
    NSString *seed = [ETHMnemonic deterministicSeedStringFromMnemonicString:_mnemonic passphrase:@"" language:@"english"];
    NSLog(@"seed: %@", seed);
    
    self.seedData = [seed dataFromHexString];

    self.keychain = [[BTCKeychain alloc] initWithSeed:self.seedData];
    
    /**
     * SHA-3 -------------keccak256
     */
    
    NSLog(@"pub: %@", BTCHexFromData([_keychain keyWithPath:@"m/44'/60'/0'/0"].uncompressedPublicKey));
    
    NSString *publicKeyStr = [BTCHexFromData([_keychain keyWithPath:@"m/44'/60'/0'/0"].uncompressedPublicKey) substringFromIndex:2];
    NSLog(@"publicStr: %@", publicKeyStr);
    
    //NSString *compressPubKey = [publicKeyStr substringToIndex:64];
    
    NSString *privateKeyStr = BTCHexFromData([_keychain keyWithPath:@"m/44'/60'/0'/0"].privateKey);
    NSLog(@"privateStr: %@", privateKeyStr);
    
    NSString *addressData = [[[_keychain keyWithPath:@"m/44'/60'/0'/0"].uncompressedPublicKey newSha3:256] substringFromIndex:24];
    NSLog(@"addressData: %@", addressData);
    
    NSString *generateAddressStr = [@"0x" stringByAppendingString:addressData];
    NSLog(@"generateAddressStr: %@", generateAddressStr);
    
    [self genertaeDerivedKey];
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}



- (void)genertaeDerivedKey {
    NSString *passwordkey = self.walletPassword.text;
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
    
    
    NSMutableData *mixEncryptPrv = [ETHAES128 encryptString: BTCHexFromData([_keychain keyWithPath:@"m/44'/60'/0'/0"].privateKey) withKey:derivedKeyStr];
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
    [self dictionaryReadFromFile];

}
//Data Persistent
- (NSString *)dictionaryFilePath {
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSLog(@"%@", documents);
    return [documents stringByAppendingPathComponent:@"secretData.txt"];
}

//字典读取文件
- (void)dictionaryReadFromFile {
    NSString *filePath = [self dictionaryFilePath];
    NSDictionary *dic = [NSDictionary dictionaryWithContentsOfFile:filePath];
    NSLog(@"privateKey :%@\n mnemonic: %@", dic[@"privateKey"], dic[@"mnemonic"]);
}

- (void)date {
    NSDate* dat = [NSDate dateWithTimeIntervalSinceNow:0];
    NSTimeInterval a=[dat timeIntervalSince1970];
    NSString *timeString = [NSString stringWithFormat:@"%.0f", a];
    NSLog(@"^^^^^^^^^^^^^^^^%@", timeString);
}


- (void)analysisKsJson {
//NSString *ksJson = @"{'address':'b5a2bab38103c45f6b918b9db83d7466375da60a','crypto':{'cipher':'aes-128-ctr','ciphertext':'c08d5969ddf4c70e96a4de5e68f45ea682cee0147a8a1b64f989509f3a3b1096','cipherparams':{'iv':'5447d7b105760d33a6b167eff84f9857'},'kdf':'scrypt','kdfparams':{'dklen':32,'n':262144,'p':1,'r':8,'salt':'e32c6e32c4d313c3ae6fd40281d8ac0550865b0f163983d6b6ca21e171a979e1'},'mac':'aa1506bc40e4db4d155a85db8e8428d0be60e348a7b585c15cb8c121437bb1d7'},'id':'21094d2e-5c0a-41b6-8435-a9580e2a4c63','version':3}";
    NSString *ksJson = @"{\"address\":\"b5a2bab38103c45f6b918b9db83d7466375da60a\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"c08d5969ddf4c70e96a4de5e68f45ea682cee0147a8a1b64f989509f3a3b1096\",\"cipherparams\":{\"iv\":\"5447d7b105760d33a6b167eff84f9857\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"e32c6e32c4d313c3ae6fd40281d8ac0550865b0f163983d6b6ca21e171a979e1\"},\"mac\":\"aa1506bc40e4db4d155a85db8e8428d0be60e348a7b585c15cb8c121437bb1d7\"},\"id\":\"21094d2e-5c0a-41b6-8435-a9580e2a4c63\",\"version\":3}";
    NSData *jsonData = [ksJson dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers
                                                          error:&err];
    NSLog(@"===============%@", dic);
    if(err) {
        NSLog(@"json解析失败：%@",err);
    }
    if (dic) {
        NSDictionary *cryptoDic = dic[@"crypto"];
        NSString *macStr = cryptoDic[@"mac"];
        NSLog(@"################%@", macStr);
        
        
    }
}

@end
