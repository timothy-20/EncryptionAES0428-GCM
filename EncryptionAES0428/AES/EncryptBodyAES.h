//
//  EncryptBodyAES.h
//  EncryptionAES0428
//
//  Created by 임정운 on 2021/04/28.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface EncryptBodyAES : NSObject

-(NSString *)generateRandomSecret;//params secret
-(NSData *)dictionaryToJSON;//params deviceInfo

-(NSString *)encryptDeviceInfo:(NSData *)deviceInfo inSecret:(NSString *)secret;

@end

NS_ASSUME_NONNULL_END
