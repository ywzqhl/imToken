//
//  KeyStoreProtocol.h
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import <Foundation/Foundation.h>


@protocol KeyStoreProtocol <NSObject>
- (NSString *)getAddress;
- (NSString *)signatureTxObj:(NSString *)signatureTxObj password:(NSString *)password;
@end
