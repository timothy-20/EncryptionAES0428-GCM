//
//  ViewController.m
//  EncryptionAES0428
//
//  Created by 임정운 on 2021/04/28.
//

#import "ViewController.h"
#import "EncryptBodyAES.h"

#include <stdlib.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    EncryptBodyAES *AES = [[EncryptBodyAES alloc] init];
    NSString *secret = [AES generateRandomSecret];
    
    NSLog(@"secret_%@", secret);
    
    int randomInt = arc4random_uniform(100);
    NSLog(@"random number_%d", randomInt);
//    Objective c에서 난수를 생성하는데 사용하는 함수.
    
    
}

@end
