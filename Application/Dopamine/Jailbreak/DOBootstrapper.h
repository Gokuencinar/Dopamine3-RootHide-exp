//
//  Bootstrapper.h
//  Dopamine
//
//  Created by Lars Fröder on 09.01.24.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const bootstrapErrorDomain;
typedef NS_ENUM(NSInteger, BootstrapErrorCode) {
    BootstrapErrorCodeFailedToGetURL            = -1,
    BootstrapErrorCodeFailedToDownload          = -2,
    BootstrapErrorCodeFailedDecompressing       = -3,
    BootstrapErrorCodeFailedExtracting          = -4,
    BootstrapErrorCodeFailedRemount             = -5,
    BootstrapErrorCodeFailedFinalising          = -6,
    BootstrapErrorCodeFailedReplacing           = -7,
};

@interface DOBootstrapper : NSObject <NSURLSessionDelegate, NSURLSessionDownloadDelegate>
{
    NSURLSession *_urlSession;
    NSURLSessionDownloadTask *_bootstrapDownloadTask;
    void (^_downloadCompletionBlock)(NSURL * _Nullable location, NSError * _Nullable error);
}

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion;
- (NSError *)updateVarJbSymlink;
- (NSError *)ensurePrivatePrebootIsWritable;
- (NSError *)installPackageManagers;
- (NSError *)finalizeBootstrap;
- (NSError *)deleteBootstrap;

@end

// Match the separate RootHidePort implementation category in DOBootstrapper.m.
// Build-time opt-in; the hidden bootstrap never shares stock /var/jb state.
@interface DOBootstrapper (RootHidePort)
+ (BOOL)rootHidePortEnabled;
+ (void)setRootHideRecoveryRequested:(BOOL)requested;
+ (nullable NSError *)preserveInterruptedRootHideBootstrap;
- (nullable NSError *)rootHidePreflightError;
+ (nullable NSString *)rootHideExistingRootWithError:(NSError * _Nullable * _Nullable)error;
+ (uint64_t)rootHideBrandForPath:(NSString *)path;
- (nullable NSError *)repairRootHideAppLinks;
@end

NS_ASSUME_NONNULL_END
