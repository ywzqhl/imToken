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
#import "libscrypt.h"
#import "AES128CTR.h"
#import "AES128Encrypt.h"
@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *walletName;
@property (weak, nonatomic) IBOutlet UITextField *walletPassword;
@property (nonatomic, strong) BTCMnemonic *mnenoic; //助记词类
@property (nonatomic, copy) NSString *mnemonic; //助记词
@property (nonatomic, strong) NSData *seedData;
@property (nonatomic, strong) BTCKeychain *keychain;
@property (nonatomic, copy) NSString *path;
@property (nonatomic, copy) NSString *address;
//@property (nonatomic, copy) NSString *seedString;
//@property (nonatomic, copy) NSString *privateKeyString;



//@property (nonatomic, copy) NSString *derivedKeyStr;
@property (nonatomic, copy) NSString *seedString;
@property (nonatomic, copy) NSString *privateKeyString;
@property (nonatomic, copy) NSString *ivSeedString; //seed nonce
@property (nonatomic, copy) NSString *ivRootPrivStr; //RootprivteKey nonce
@property (nonatomic, copy) NSString *ivHDPathPriv;
@property (nonatomic, copy) NSString *ivPriv; //私钥nonce
@property (nonatomic, strong) NSMutableString *derivedKeyStr; //derivedKey

@end

@implementation ViewController
- (NSData *)AESIv {
    return [AES128CTR randomDataOfLength:kCCBlockSizeAES128];
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
    NSLog(@"HDDDDDDDDDDDD:%@", encHdPathPriv);
    NSDictionary *priv = @{@"key":aesPriv, @"nonce":self.ivPriv};
    NSDictionary *encPrivKeys = @{self.privateKeyString:priv};
    NSArray *addresses = @[self.privateKeyString];
    NSDictionary *m_0_0_0 = @{@"info":info, @"encHdPathPriv":encHdPathPriv, @"hdIndex":@10 ,@"encPrivKeys":encPrivKeys, @"addresses":addresses};
    NSDictionary *encSeed = @{@"encStr": BTCHexFromData(aesSeed), @"nonce": self.ivSeedString};
    NSDictionary *encHdRootPriv = @{@"encStr": BTCHexFromData(aesRootPriv), @"nonce":self.ivRootPrivStr};
    NSDictionary *ksData = @{@"m/0'/0'/0'": m_0_0_0};
    NSDictionary *bigDic = @{@"encSeed":encSeed, @"ksData":ksData, @"encHdRootPriv":encHdRootPriv, @"version":@2};
    NSLog(@"##############%@", bigDic);
    NSString *ksJsonString = [self returnJSONStringWithDictionary:bigDic];
    NSDate *currentDate = [NSDate date];//获取当前时间，日期
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"YYYY-MM-dd-hh-mm-ss-SS"];
    NSString *dateString = [dateFormatter stringFromDate:currentDate];
    NSLog(@"dateString:%@",dateString);
    //数据持久化
    NSString *jsonpath = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject]stringByAppendingPathComponent:[[@"HD-" stringByAppendingString:dateString] stringByAppendingString:self.address]];
    BOOL isSuccess = [ksJsonString writeToFile:jsonpath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"%@", isSuccess ? @"successful" : @"failed");
    
    
    NSArray *path = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [path objectAtIndex:0];
    NSString *fileDirectory = [documentsDirectory stringByAppendingPathComponent:[[@"HD-" stringByAppendingString:dateString] stringByAppendingString:self.address]];
    NSLog(@"PPPPPPPPPPpath%@", fileDirectory);
    NSString *dicStr = [NSString stringWithContentsOfFile:fileDirectory encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"^^^^^^^^^^^^^^^^^^^^^%@", dicStr);
    
}

- (NSData *)seedData {
    if (!_seedData) {
        self.seedData = [[NSData alloc] init];
    }
    return _seedData;
}

/**
 * generate PRN
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
/**
 * generate 128bit random number
 */
- (NSData *)random128Bit {
    unsigned char buf[16];
    arc4random_buf(buf, sizeof(buf));
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}

- (NSDictionary *)dictionaryWithJsonString:(NSString *)jsonString {
    
    if (jsonString == nil) {
        
        return nil;
        
    }
    
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSError *err;
    
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                         
                                                        options:NSJSONReadingMutableContainers
                         
                                                          error:&err];
    
    if(err) {
        
        NSLog(@"json解析失败：%@",err);
        
        return nil;
        
    }
    
    return dic;
    
}

//词典转换为字符串

- (NSString*)dictionaryToJson:(NSDictionary *)dic

{
    
    NSError *parseError = nil;
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&parseError];
    
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
}


- (NSString *)returnJSONStringWithDictionary:(NSDictionary *)dictionary{
    
    //系统自带
    
    //    NSError * error;
    
    //    NSData * jsonData = [NSJSONSerialization dataWithJSONObject:dictionary options:kNilOptions error:&error];
    
    //    NSString * jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
    //自定义
    
    NSString *jsonStr = @"{";
    
    NSArray * keys = [dictionary allKeys];
    
    for (NSString * key in keys) {
        
        jsonStr = [NSString stringWithFormat:@"%@\"%@\":\"%@\",",jsonStr,key,[dictionary objectForKey:key]];
        
    }
    
    jsonStr = [NSString stringWithFormat:@"%@%@",[jsonStr substringWithRange:NSMakeRange(0, jsonStr.length-1)],@"}"];
    
    return jsonStr;
    
}
- (void)viewDidLoad {
    [super viewDidLoad];
    if ([self.mnemonic isEqualToString:@""] || self.mnemonic == nil) {
        self.mnemonic = [ETHMnemonic generateMnemonicString:@128 language:@"english"];
        NSLog(@"Mnemonic: %@", _mnemonic);
    }
    self.seedString = [ETHMnemonic deterministicSeedStringFromMnemonicString:_mnemonic passphrase:@"" language:@"english"];
    NSLog(@"seedString: %@", self.seedString);
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
    
    uint64_t num = 1 <<18;
    NSLog(@"%llu", num);
    unsigned char derivedkey[32];
    NSString *s = [self generateSalt256];
    const uint8_t *salt = [s dataFromHexString].bytes;
    libscrypt_scrypt([@"123456" dataUsingEncoding:NSUTF8StringEncoding].bytes, [@"12345" dataUsingEncoding:NSUTF8StringEncoding].length, salt, [s dataFromHexString].length, 262144 , 8, 1, derivedkey, 32);
    self.derivedKeyStr = [[NSMutableString alloc] init];//encoding
    for (int i = 0 ; i < 32 ; ++i)
    {
        [self.derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
    }
    NSData *ivData = [AES128CTR randomDataOfLength:kCCBlockSizeAES128];
    
    
    NSMutableData *data = [AES128Encrypt encryptString:self.seedString withKey:_derivedKeyStr iv:ivData];
    NSLog(@"data: %@", BTCHexFromData(data));
    NSString *decryptStr = [AES128Encrypt decryptData:data withKey:_derivedKeyStr iv:ivData];
    NSLog(@"seedStr: %@", decryptStr);
    
    NSLog(@"%@", BTCHexFromData(ivData));
    
    
    
    
    [self writeKsJson];
    
    
//    NSData *data = [AES128CTR encryptedDataForData:self.seedData password:@"12345" iv:ivData salt:[derivedKeyStr dataFromHexString] error:nil];
//    NSLog(@"seed:%@", BTCHexFromData(self.seedData));
//    NSLog(@"######%@", BTCHexFromData(data));
    
    
    
    
//    NSData *data1 = [AES128CTR AESKeyForPassword:@"12345" salt:[derivedKeyStr dataFromHexString]];
//    NSLog(@"data1: %@",BTCHexFromData(data1));
    
    
    
    
//    NSDictionary *dict = @{@"aaa":@"11",@"bb":@"22",@"cc":@"33"};
//    
//    NSString *str = [self dictionaryToJson:dict];
//    
//    NSDictionary *dict1 = [self dictionaryWithJsonString:str];
//    
//    NSLog(@"%@",str);
//    
//    NSLog(@"%@",dict1);
//
//    
    
    
    //libscrypt_scrypt(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t,
                     //uint32_t, uint32_t, /*@out@*/ uint8_t *, size_t);
    
    //self.mnemonic = [ETHMnemonic generateMnemonicString:@128 language:@"english"];
      //  NSLog(@"Mnemonic: %@", _mnemonic);
    
//    NSString *seed = [ETHMnemonic deterministicSeedStringFromMnemonicString:@"people share marine skull sister hand act adjust wool creek mule card" passphrase:@"" language:@"english"];
//    self.seedData = [seed dataFromHexString];
//    self.keychain = [[BTCKeychain alloc] initWithSeed:self.seedData];
//    NSLog(@"ROOT: %@", _keychain.extendedPrivateKey);
//    /**
//     * SHA-3 -------------keccak256
//     */
//   
//        _path = @"m/44'/60'/0'/0";
//
//    NSLog(@"pub: %@", BTCHexFromData([_keychain keyWithPath:_path].uncompressedPublicKey));
//    
//    NSString *publicKeyStr = [BTCHexFromData([_keychain keyWithPath:_path].uncompressedPublicKey) substringFromIndex:2];
//    NSLog(@"publicStr: %@", publicKeyStr);
//    
//    //NSString *compressPubKey = [publicKeyStr substringToIndex:64];
//    
//    NSString *privateKeyStr = BTCHexFromData([_keychain keyWithPath:_path].privateKey);
//    NSLog(@"privateStr: %@", privateKeyStr);
//    
//    NSString *tempPub = [BTCHexFromData([_keychain keyWithPath:_path].uncompressedPublicKey) substringFromIndex:2];
//    
//    NSString *addressData = [[[tempPub dataFromHexString] newSha3:256] substringFromIndex:24];
//    NSLog(@"addressData: %@", addressData);
//    
//    self.address = [@"0x" stringByAppendingString:addressData];
//    NSLog(@"generateAddressStr: %@", self.address);
    
    
    
    
//    uint64_t num = 1 <<18;
//    NSLog(@"%llu", num);
//    unsigned char derivedkey[32];
//    const uint8_t *salt = [@"dcb0886e48eaf8c0611afe4f0beaa112451b38ccc66fc61f9e2c2988c43dcb66" dataFromHexString].bytes;
//    libscrypt_scrypt([@"password" dataUsingEncoding:NSUTF8StringEncoding].bytes, [@"password" dataUsingEncoding:NSUTF8StringEncoding].length, salt, [@"dcb0886e48eaf8c0611afe4f0beaa112451b38ccc66fc61f9e2c2988c43dcb66" dataFromHexString].length, 256 , 8, 1, derivedkey, 32);
//    NSMutableString* derivedKeyStr = [[NSMutableString alloc] init];//encoding
//    for (int i = 0 ; i < 32 ; ++i)
//    {
//        [derivedKeyStr appendFormat: @"%02x", derivedkey[i]];
//    }
//    NSString *halfDerivedKeyStr = [derivedKeyStr substringFromIndex:32];
//    NSString *m = [halfDerivedKeyStr stringByAppendingString:@"bab660cd77814f69a84608cf05a3d00983d8c79eeeaa5f2d3ce47df0cbc8340b"];
//    NSString *mac = [[m dataFromHexString] newSha3:256];
//    NSLog(@"mac: %@", mac.lowercaseString);
    
    
    
    
    
    
    //NSLog(@"%@", [self generateSalt256]);

    
    
//    NSDate *currentDate = [NSDate date];//获取当前时间，日期
//    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
//    [dateFormatter setDateFormat:@"YYYY-MM-dd-hh-mm-ss-SS"];
//    NSString *dateString = [dateFormatter stringFromDate:currentDate];
//    NSLog(@"dateString:%@",dateString);
    
    //[self date];
    //[self analysisKsJson];
    // Do any additional setup after loading the view, typically from a nib.
//     NSString *ksJson = @"{\"address\":\"b5a2bab38103c45f6b918b9db83d7466375da60a\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"c08d5969ddf4c70e96a4de5e68f45ea682cee0147a8a1b64f989509f3a3b1096\",\"cipherparams\":{\"iv\":\"5447d7b105760d33a6b167eff84f9857\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"e32c6e32c4d313c3ae6fd40281d8ac0550865b0f163983d6b6ca21e171a979e1\"},\"mac\":\"aa1506bc40e4db4d155a85db8e8428d0be60e348a7b585c15cb8c121437bb1d7\"},\"id\":\"21094d2e-5c0a-41b6-8435-a9580e2a4c63\",\"version\":3}";
//    V3Keystore *v = [[V3Keystore alloc] initWithPassword:@"111111" ksJson:ksJson];
//    NSLog(@"&&&&&&&&&&&&&&&&&&&&&&&&&%@", [v getAddress]);
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
