//
//  EncryptBodyAES.m
//  cubelogin
//
//  Created by 임정운 on 2021/04/28.
//  Copyright © 2021 Aircuve. All rights reserved.
//

#import "EncryptBodyAES.h"

#import <AesGcm/IAGAesGcm.h>
#import <CommonCrypto/CommonCrypto.h>

#import <UIKit/UIKit.h>

@interface EncryptBodyAES ()

@property(nonatomic, strong) NSMutableDictionary *mDeviceInfo;
@property(nonatomic, strong) NSData *secretAES;

@end

@implementation EncryptBodyAES

-(void)dealloc
{
    self.mDeviceInfo = nil;
    self.secretAES = nil;
}

-(id)init
{
    self = [super init];
    if (self) {
        self.mDeviceInfo = [[NSMutableDictionary alloc] init];
    }
    
    return self;
}

#pragma mark - device Info with JSON String

-(NSDictionary *)setDeviceInfoWithDictionary
{
    NSMutableDictionary *deviceDictionary = [NSMutableDictionary dictionary];
    [deviceDictionary setObject:[UIDevice currentDevice].identifierForVendor.UUIDString forKey:@"deviceId"];
    [deviceDictionary setObject:[UIDevice currentDevice].name forKey:@"deviceName"];
    [deviceDictionary setObject:@"ios" forKey:@"os"];
    [deviceDictionary setObject:[UIDevice currentDevice].systemVersion forKey:@"osVersion"];
    [deviceDictionary setObject:[NSBundle.mainBundle.infoDictionary objectForKey:@"CFBundleShortVersionString"] forKey:@"appVersion"];
    [deviceDictionary setObject:@"(null)" forKey:@"token"];

    self.mDeviceInfo = deviceDictionary;
    
    return deviceDictionary;
}

-(NSData *)dictionaryToJSON
{
    NSError *error;
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:[self setDeviceInfoWithDictionary] options:NSJSONWritingPrettyPrinted error:&error];
    
    if(! jsonData) {
        NSLog(@"Error Ocurred: %@", error);
        
        return nil;
    }
    
    return jsonData;
}



#pragma mark - convert hexString with NSString

-(NSData *)hexStringToData:(NSString *)hexString
{
    NSMutableData *hexStringToSend = [NSMutableData data];
    unsigned char whole_byte;
    
    char byte_chars[3] = {'\0', '\0', '\0'};
    
    for (int i = 0; i < [hexString length]/2; i++) {
        byte_chars[0] = [hexString characterAtIndex:i*2];
        byte_chars[1] = [hexString characterAtIndex:i*2+1];
        
        whole_byte = strtol(byte_chars, NULL, 16);
        [hexStringToSend appendBytes:&whole_byte length:1];
    }
    
    return hexStringToSend;
    
//    NSAssert(0 == [hexString length] % 2, @"Hex String should have an even number of digital (%@)", hexString);
//    강제 디버깅, objc 디버깅에서 사용된다. 하지만 역시 선호하는 방식은 아니다.
}

-(NSString *)dataToHexString:(NSData *)inData
{
    const unsigned char *dataBuffer = (const unsigned char *)[inData bytes];
    
    if(! dataBuffer) {
        NSLog(@"Error Ocurred: missing dataBuffer");
        
        return nil;
    }
    
    NSUInteger dataLength = [inData length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];
    //이는 위에서 random secret을 추출할 때와 같은 원리이다.(이하 생략)
    
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    }
    
    return [NSString stringWithString:hexString];
}

#pragma mark - encrypt with secret

-(NSString *)generateRandomSecret
{
    uint8_t randomBytes[16];
    int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
    
    if(result == 0) {
        NSMutableString *uuidStringReplacement = [[NSMutableString alloc] initWithCapacity:16*2];
        //16진수 문자열로 변환할 시 길이가 2배가 되므로 Capacity 또한 두배를 잡아줘야 한다.
        
        for (NSInteger index = 0; index < 16; index++) {
            [uuidStringReplacement appendFormat:@"%02x", randomBytes[index]];
        }
        NSLog(@"uuidStringReplacement_%@", uuidStringReplacement);
        
        return uuidStringReplacement;
    } else {
        NSLog(@"SEcRandomCopyByptes failed for some reason");
    }
    
    return nil;
}

-(NSString *)encryptDeviceInfo:(NSData *)deviceInfo inSecret:(NSString *)secret
{
//    NSString *ivStr = [secret substringToIndex:24];
//
//    NSData *PlainData = [plainString dataUsingEncoding:NSUTF8StringEncoding];
//
//    NSData *IV = [self hexStringToData:ivStr];
//    NSData *secretKey = [self hexStringToData:secret];
    
    NSData *secretKey = [self hexStringToData:secret];
    NSData *IV = [self hexStringToData:[secret substringToIndex:24]];
    NSData *aad = [NSData data];
    
    IAGCipheredData *cipheredData = [IAGAesGcm cipheredDataByAuthenticatedEncryptingPlainData:deviceInfo
                                                              withAdditionalAuthenticatedData:aad
                                                                      authenticationTagLength:IAGAuthenticationTagLength128
                                                                         initializationVector:IV
                                                                                          key:secretKey
                                                                                        error:nil];
    
    NSData *cipehrBuffer = [NSData dataWithBytes:cipheredData.cipheredBuffer length:cipheredData.cipheredBufferLength];
    NSData *extraBuffer = [NSData dataWithBytes:cipheredData.authenticationTag length:cipheredData.authenticationTagLength];
    
    NSMutableData *fullBuffer = [[NSMutableData alloc] initWithData:IV];
    [fullBuffer appendData:cipehrBuffer];
    [fullBuffer appendData:extraBuffer];
    
    NSString *cipherWithHex = [self dataToHexString:fullBuffer];
    
    return cipherWithHex;
}


@end
