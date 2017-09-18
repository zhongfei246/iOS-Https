//
//  ViewController.m
//  Https
//
//  Created by lizhongfei on 11/9/17.
//  Copyright © 2017年 lizhongfei. All rights reserved.
//

#import "ViewController.h"
#import "AFNetworking.h"

/**
    注：第一：https有效
          第二：cer有效
          第三：如果贵公司的测试环境也是https的，就可以直接把NSAppTransportSecurity即ATS配置的根节点中的NSAllowsAritraryLoads删掉了，如果测试环境是http的，那测试时就不用校验https，加上ATS配置NSAllowsAritraryLoads为YES即可，但是上线（App Store）的时候需要去掉，苹果把https延期了，据说如果实行的话适配了https但是ATS的NSAllowsAritraryLoads仍为YES的话会被拒。
 */


@interface ViewController ()<NSURLSessionDataDelegate>

@end

@implementation ViewController

-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
//    [self adaptationMode1];
    [self adaptationMode2];
}

#pragma mark ---------------------------------
#pragma mark https处理方法一：NSURLSession（自己写接口请求，不借助afn）
-(void)adaptationMode1{
    //创建会话对象
    NSURLSession * session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration] delegate:self delegateQueue:[NSOperationQueue mainQueue]];
    
    NSURLSessionDataTask * dataTask = [session dataTaskWithURL:[NSURL URLWithString:@"公司的https链接"] completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        //解析数据
        NSLog(@"%@---%@",[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding],error);
    }];
    //执行task
    [dataTask resume];
    
}
#pragma mark ---------------------------------
#pragma mark NSURLSessionDataDelegate
//如果发送的请求是https的,那么才会调用该方法
/**
 ATS
 
 ATS限制使用HTTP, 数据请求尽量通过HTTPS加密传输,
 且HTTPS的请求也要满足以下规定:
 
 1.传输层协议(TLS)至少为1.2版本
 2.连接的加密方式要提供Forward Secrecy,支持如下加密算法详见苹果官方文档
 3.证书至少要使用一个SHA256的指纹与任一个2048位或者更高位的RSA密钥，或者是256位或者更高位的ECC密钥。如果不符合其中一项，请求将被中断并返回nil.
 
 上面新增的配置中的NSAppTransportSecurity是ATS配置的根节点，配置了节点表示告诉系统要走自定义的ATS设置。而NSAllowsAritraryLoads节点则是控制是否禁用ATS特性，设置YES就是禁用ATS功能。
 如果请求源是HTTPS,则需要根据是否满足以上三个条件来针对性地配置plist

 */
-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler{
    
    //判断证书类型，如果是服务器信任证书就往下走，否则直接return
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust]) {
        do
        {
            SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
            NSCAssert(serverTrust != nil, @"serverTrust is nil");
            if(nil == serverTrust)
                break; /* failed */
            /**
             *  导入多张CA证书（Certification Authority，支持SSL证书以及自签名的CA），请替换掉你的证书名称
             */
            NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"cer文件名" ofType:@"cer"];//自签名证书
            NSData* caCert = [NSData dataWithContentsOfFile:cerPath];
            NSCAssert(caCert != nil, @"caCert is nil");
            if(nil == caCert)
                break; /* failed */
            SecCertificateRef caRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)caCert);
            NSCAssert(caRef != nil, @"caRef is nil");
            if(nil == caRef)
                break; /* failed */
            //可以添加多张证书
            NSArray *caArray = @[(__bridge id)(caRef)];
            NSCAssert(caArray != nil, @"caArray is nil");
            if(nil == caArray)
                break; /* failed */
            //将读取的证书设置为服务端帧数的根证书
            OSStatus status = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)caArray);
            NSCAssert(errSecSuccess == status, @"SecTrustSetAnchorCertificates failed");
            if(!(errSecSuccess == status))
                break; /* failed */
            SecTrustResultType result = -1;
            //通过本地导入的证书来验证服务器的证书是否可信
            status = SecTrustEvaluate(serverTrust, &result);
            if(!(errSecSuccess == status))
                break; /* failed */
            NSLog(@"stutas:%d",(int)status);
            NSLog(@"Result: %d", result);
            BOOL allowConnect = (result == kSecTrustResultUnspecified) || (result == kSecTrustResultProceed);
            if (allowConnect) {
                NSLog(@"success");
            }else {
                NSLog(@"error");
            }
            /* kSecTrustResultUnspecified and kSecTrustResultProceed are success */
            if(! allowConnect)
            {
                break; /* failed */
            }
#if 0
            /* Treat kSecTrustResultConfirm and kSecTrustResultRecoverableTrustFailure as success */
            /*   since the user will likely tap-through to see the dancing bunnies */
            if(result == kSecTrustResultDeny || result == kSecTrustResultFatalTrustFailure || result == kSecTrustResultOtherError)
                break; /* failed to trust cert (good in this case) */
#endif
            // The only good exit point
            NSLog(@"信任该证书");
            NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
            return [[challenge sender] useCredential: credential
                          forAuthenticationChallenge: challenge];
        }
        while(0);
    }
    
    //NSURLSessionAuthChallengeDisposition 如何处理证书
    /*
     NSURLSessionAuthChallengeUseCredential = 0, 使用该证书 安装该证书
     NSURLSessionAuthChallengePerformDefaultHandling = 1, 默认采用的方式,该证书被忽略
     NSURLSessionAuthChallengeCancelAuthenticationChallenge = 2, 取消请求,证书忽略
     NSURLSessionAuthChallengeRejectProtectionSpace = 3,          拒绝
     */
#warning 也可以不校验证书，直接授权，不过一般我们为了安全起见我们是需要校验证书的，只有信任证书才让请求成功返回数据，所以不校验证书的这种不推荐
//    NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
//    completionHandler(NSURLSessionAuthChallengeUseCredential,credential);
}
#pragma mark ---------------------------------
#pragma mark afn的https处理方法
-(void)adaptationMode2
{
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    
    //更改解析方式
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    
#warning  第一种:不校验证书（不推荐）
//    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
//    
//    // allowInvalidCertificates 是否允许无效证书（也就是自建的证书），默认为NO
//    // 如果是需要验证自建证书，需要设置为YES
//    securityPolicy.allowInvalidCertificates = YES;
    //不需要校验域名
//    securityPolicy.validatesDomainName = NO;
    
    
    //第二种：可以使用公司运维给的证书文件转成cer格式拉到项目中，在这个地方校验
    // /先导入证书
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"工程里的cer文件名" ofType:@"cer"];//证书的路径
    NSData *certData = [NSData dataWithContentsOfFile:cerPath];
    
    // AFSSLPinningModeCertificate 使用证书验证模式
    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    // allowInvalidCertificates 是否允许无效证书（也就是自建的证书），默认为NO
    // 如果是需要验证自建证书，需要设置为YES
    securityPolicy.allowInvalidCertificates = YES;
    
    //validatesDomainName 是否需要验证域名，默认为YES；
    //假如证书的域名与你请求的域名不一致，需把该项设置为NO；如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
    //置为NO，主要用于这种情况：客户端请求的是子域名，而证书上的是另外一个域名。因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
    //如置为NO，建议自己添加对应域名的校验逻辑。
    securityPolicy.validatesDomainName = YES;
    
    securityPolicy.pinnedCertificates = [NSSet setWithObjects:certData, nil];
    
    //调用manager的setSecurityPolicy
    [manager setSecurityPolicy:securityPolicy];
    
    
    [manager GET:@"公司的https后台链接" parameters:nil progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        NSLog(@"success---%@",[[NSString alloc]initWithData:responseObject encoding:NSUTF8StringEncoding]);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        NSLog(@"error---%@",error);
    }];
}

@end
