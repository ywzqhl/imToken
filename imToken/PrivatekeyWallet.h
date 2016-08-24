//
//  PrivatekeyWallet.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/23.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KeyStoreProtocol.h"
@interface PrivatekeyWallet : NSObject<KeyStoreProtocol>
@property (nonatomic, copy) NSString *password;
@property (nonatomic, copy) NSString *privatekey;

- (instancetype)initWithPrivatekey:(NSString *)privatekey password:(NSString *)password;

@end
