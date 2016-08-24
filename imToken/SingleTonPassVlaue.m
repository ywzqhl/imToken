//
//  SingleTonPassVlaue.m
//  imToken
//
//  Created by 刘鸿博 on 16/8/22.
//  Copyright © 2016年 刘鸿博. All rights reserved.
//

#import "SingleTonPassVlaue.h"

@implementation SingleTonPassVlaue
+ (SingleTonPassVlaue *)shareSingleton{
    static SingleTonPassVlaue * ton = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        ton = [[self alloc] init];
    });
    return ton;
    
}@end
