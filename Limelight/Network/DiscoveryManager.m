//
//  DiscoveryManager.m
//  Moonlight
//
//  Created by Diego Waxemberg on 1/1/15.
//  Copyright (c) 2015 Moonlight Stream. All rights reserved.
//

#import "DiscoveryManager.h"
#import "CryptoManager.h"
#import "HttpManager.h"
#import "Utils.h"
#import "DataManager.h"
#import "DiscoveryWorker.h"
#import "ServerInfoResponse.h"
#import "IdManager.h"

#include <Limelight.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

static NSString * const MoonlightAutoDiscoverNewHostsDefaultsKey = @"autoDiscoverNewHosts";

static BOOL MoonlightShouldAutoDiscoverNewHosts(void) {
    id value = [[NSUserDefaults standardUserDefaults] objectForKey:MoonlightAutoDiscoverNewHostsDefaultsKey];
    if (value == nil) {
        return YES;
    }

    return [[NSUserDefaults standardUserDefaults] boolForKey:MoonlightAutoDiscoverNewHostsDefaultsKey];
}

@implementation DiscoveryManager {
    NSMutableArray* _hostQueue;
    NSMutableSet* _pausedHosts;
    id<DiscoveryCallback> _callback;
    MDNSManager* _mdnsMan;
    NSOperationQueue* _opQueue;
    NSString* _uniqueId;
    NSData* _cert;
    BOOL shouldDiscover;
}

- (id)initWithHosts:(NSArray *)hosts andCallback:(id<DiscoveryCallback>)callback {
    self = [super init];
    
    // Using addHostToDiscovery ensures no duplicates
    // will make it into the list from the database
    _callback = callback;
    shouldDiscover = NO;
    _hostQueue = [NSMutableArray array];
    _pausedHosts = [NSMutableSet set];
    for (TemporaryHost* host in hosts)
    {
        [self addHostToDiscovery:host];
    }
    [_callback updateAllHosts:_hostQueue];
    
    _opQueue = [[NSOperationQueue alloc] init];
    _mdnsMan = [[MDNSManager alloc] initWithCallback:self];
    [CryptoManager generateKeyPairUsingSSL];
    _uniqueId = [IdManager getUniqueId];
    _cert = [CryptoManager readCertFromFile];
    return self;
}

+ (BOOL) isAddressLAN:(in_addr_t)addr {
    addr = htonl(addr);
    
    // 10.0.0.0/8
    if ((addr & 0xFF000000) == 0x0A000000) {
        return YES;
    }
    // 172.16.0.0/12
    else if ((addr & 0xFFF00000) == 0xAC100000) {
        return YES;
    }
    // 192.168.0.0/16
    else if ((addr & 0xFFFF0000) == 0xC0A80000) {
        return YES;
    }
    // 169.254.0.0/16
    else if ((addr & 0xFFFF0000) == 0xA9FE0000) {
        return YES;
    }
    // 100.64.0.0/10 - RFC6598 official CGN address (shouldn't see this in a LAN)
    else if ((addr & 0xFFC00000) == 0x64400000) {
        return YES;
    }
    
    return NO;
}

// This ensures that only RFC 1918 IPv4 addresses can be passed to
// the Add PC dialog. This is required to comply with Apple App Store
// Guideline 4.2.7a.
+ (BOOL) isProhibitedAddress:(NSString*)address {
#ifdef ENABLE_APP_STORE_RESTRICTIONS
    struct addrinfo hints;
    struct addrinfo* result;
    int err;
    
    NSString* hostAddress;
    [Utils parseAddress:address intoHost:&hostAddress andPort:nil];

    // We're explicitly using AF_INET here because we don't want to
    // ever receive a synthesized IPv6 address here, even on NAT64.
    // IPv6 addresses are not restricted here because we cannot easily
    // tell whether they are local or not.
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    err = getaddrinfo([hostAddress UTF8String], NULL, &hints, &result);
    if (err != 0 || result == NULL) {
        Log(LOG_W, @"getaddrinfo(%@) failed: %d", hostAddress, err);
        return NO;
    }
    
    if (result->ai_family != AF_INET) {
        // This should never happen due to our hints
        assert(result->ai_family == AF_INET);
        Log(LOG_W, @"Unexpected address family: %d", result->ai_family);
        freeaddrinfo(result);
        return NO;
    }
    
    BOOL ret = ![DiscoveryManager isAddressLAN:((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr];
    freeaddrinfo(result);

    return ret;
#else
    return NO;
#endif
}

- (ServerInfoResponse*) getServerInfoResponseForAddress:(NSString*)address {
    HttpManager* hMan = [[HttpManager alloc] initWithHost:address uniqueId:_uniqueId serverCert:nil];
    ServerInfoResponse* serverInfoResponse = [[ServerInfoResponse alloc] init];
    // Use fast failure for discovery (2s timeout) to speed up status updates
    [hMan executeRequestSynchronously:[HttpRequest requestForResponse:serverInfoResponse withUrlRequest:[hMan newServerInfoRequest:true] fallbackError:401 fallbackRequest:[hMan newHttpServerInfoRequest:true]]];
    return serverInfoResponse;
}

- (void) discoverHost:(NSString *)hostAddress withCallback:(void (^)(TemporaryHost *, NSString*))callback {
    BOOL prohibitedAddress = [DiscoveryManager isProhibitedAddress:hostAddress];
    NSString* prohibitedAddressMessage = [NSString stringWithFormat: @"Moonlight only supports adding PCs on your local network on %s.",
    #if TARGET_OS_TV
                                   "tvOS"
    #else
                                   "iOS"
    #endif
                             ];
    ServerInfoResponse* serverInfoResponse = [self getServerInfoResponseForAddress:hostAddress];
    
    TemporaryHost* host = nil;
    if ([serverInfoResponse isStatusOk]) {
        host = [[TemporaryHost alloc] init];
        host.activeAddress = host.address = hostAddress;
        host.state = StateOnline;
        [serverInfoResponse populateHost:host];
        
        // Check if this is a new PC
        if (![self getHostInDiscovery:host.uuid]) {
            // Enforce LAN restriction for App Store Guideline 4.2.7a
            if ([DiscoveryManager isProhibitedAddress:hostAddress]) {
                // We have a prohibited address. This might be because the user specified their WAN address
                // instead of their LAN address. If that's the case, we'll try their LAN address and if we
                // can reach it through that address, we'll allow it.
                ServerInfoResponse* lanInfo = [self getServerInfoResponseForAddress:host.localAddress];
                if ([lanInfo isStatusOk]) {
                    TemporaryHost* lanHost = [[TemporaryHost alloc] init];
                    [lanInfo populateHost:lanHost];
                    
                    if (![lanHost.uuid isEqualToString:host.uuid]) {
                        // This is a different host, so it's prohibited
                        prohibitedAddress = YES;
                    }
                    else {
                        // This is the same host that is reachable on the LAN
                        prohibitedAddress = NO;
                    }
                }
                else {
                    // LAN request failed, so it's a prohibited address
                    prohibitedAddress = YES;
                }
            }
            else {
                // It's an RFC 1918 IPv4 address or IPv6 address which counts as LAN
                prohibitedAddress = NO;
            }
            
            if (prohibitedAddress) {
                callback(nil, prohibitedAddressMessage);
                return;
            }
            
            NSString* cleanHostAddress;
            [Utils parseAddress:hostAddress intoHost:&cleanHostAddress andPort:nil];
            if ([DiscoveryManager isAddressLAN:inet_addr([cleanHostAddress UTF8String])]) {
                // Don't send a STUN request if we're connected to a VPN. We'll likely get the VPN
                // gateway's external address rather than the external address of the LAN.
                if (![Utils isActiveNetworkVPN]) {
                    // This host was discovered over a permissible LAN address, so we can update our
                    // external address for this host.
                    struct in_addr wanAddr;
                    int err = LiFindExternalAddressIP4("stun.moonlight-stream.org", 3478, &wanAddr.s_addr);
                    if (err == 0) {
                        char addrStr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &wanAddr, addrStr, sizeof(addrStr));
                        host.externalAddress = [NSString stringWithFormat: @"%s", addrStr];
                    }
                }
            }
        }
        
        if (![self addHostToDiscovery:host]) {
            callback(nil, @"Host information updated");
        } else {
            callback(host, nil);
        }
    } else if (!prohibitedAddress) {
        callback(nil, NSLocalizedString(@"Could not connect to host. Ensure GameStream is enabled in GeForce Experience on your PC.", @"Host connect failure"));
    } else {
        callback(nil, prohibitedAddressMessage);
    }
}

- (void) resetDiscoveryState {
    // Allow us to rediscover hosts that were already found before
    [_mdnsMan forgetHosts];
}

- (void) startDiscovery {
    if (shouldDiscover) {
        return;
    }
    
    Log(LOG_I, @"Starting discovery");
    shouldDiscover = YES;
    [_mdnsMan searchForHosts];
    
    @synchronized (_hostQueue) {
        for (TemporaryHost* host in _hostQueue) {
            if (![_pausedHosts containsObject:host]) {
                [_opQueue addOperation:[self createWorkerForHost:host]];
            }
        }
    }
}

- (void) stopDiscovery {
    if (!shouldDiscover) {
        return;
    }
    
    Log(LOG_I, @"Stopping discovery");
    shouldDiscover = NO;
    [_mdnsMan stopSearching];
    [_opQueue cancelAllOperations];
}

- (void) stopDiscoveryBlocking {
    Log(LOG_I, @"Stopping discovery and waiting for workers to stop");
    
    if (shouldDiscover) {
        shouldDiscover = NO;
        [_mdnsMan stopSearching];
        [_opQueue cancelAllOperations];
    }
    
    // Ensure we always wait, just in case discovery
    // was stopped already but in an async manner that
    // left operations in progress.
    [_opQueue waitUntilAllOperationsAreFinished];
    
    Log(LOG_I, @"All discovery workers stopped");
}

// 仅按 UUID 匹配无法处理「记录里的地址已过期、mDNS 又拿不到 UUID」的情形：
// 地址过期 → serverinfo 探测失败 → UUID 永远拿不到 → 新地址永远写不回记录。
// 这里补充按地址 / 主机名的兜底匹配，用于打破该死循环。
- (TemporaryHost *) getHostInDiscoveryByAddressOrName:(TemporaryHost *)host {
    NSString *localAddress = host.localAddress;
    NSString *shortHostName = host.name ?: @"";
    if ([shortHostName hasSuffix:@".local."]) {
        shortHostName = [shortHostName substringToIndex:shortHostName.length - 7];
    } else if ([shortHostName hasSuffix:@"."]) {
        shortHostName = [shortHostName substringToIndex:shortHostName.length - 1];
    }

    @synchronized (_hostQueue) {
        for (TemporaryHost *discoveredHost in _hostQueue) {
            if (localAddress.length > 0) {
                if ([discoveredHost.localAddress isEqualToString:localAddress] ||
                    [discoveredHost.address isEqualToString:localAddress] ||
                    [discoveredHost.activeAddress isEqualToString:localAddress]) {
                    return discoveredHost;
                }
            }
            if (shortHostName.length > 0 && discoveredHost.name.length > 0) {
                if ([discoveredHost.name caseInsensitiveCompare:shortHostName] == NSOrderedSame) {
                    return discoveredHost;
                }
            }
        }
    }

    return nil;
}

// 把新发现的主机信息合并到已有记录中。
// 注意：localAddress / externalAddress / ipv6Address 属于自动发现字段，
// 主机更换 IP 后必须允许被新值覆盖，否则记录会永久停留在一个已不可达的旧地址上。
// 这里刻意不整块复制 TemporaryHost，避免把不带配对信息的探测结果覆盖到已配对记录上。
- (void) mergeDiscoveredHost:(TemporaryHost *)host
            intoExistingHost:(TemporaryHost *)existingHost
                 updateState:(BOOL)updateState {
    // 主地址槽位只填空位，避免覆盖用户手动指定的地址
    if (host.address.length > 0) {
        BOOL alreadyKnown = [existingHost.address isEqualToString:host.address] ||
                            [existingHost.localAddress isEqualToString:host.address] ||
                            [existingHost.externalAddress isEqualToString:host.address] ||
                            [existingHost.ipv6Address isEqualToString:host.address];
        if (!alreadyKnown) {
            if (existingHost.address.length == 0) {
                existingHost.address = host.address;
            } else if (existingHost.localAddress.length == 0) {
                existingHost.localAddress = host.address;
            } else if (existingHost.externalAddress.length == 0) {
                existingHost.externalAddress = host.address;
            } else if (existingHost.ipv6Address.length == 0) {
                existingHost.ipv6Address = host.address;
            } else {
                existingHost.address = host.address;
            }
        }
    }

    // 自动发现字段：允许用最新发现的值覆盖过期地址
    if (host.localAddress.length > 0 && ![host.localAddress isEqualToString:existingHost.localAddress]) {
        Log(LOG_I, @"%@ 的本地地址已更新：%@ -> %@", existingHost.name,
            existingHost.localAddress.length > 0 ? existingHost.localAddress : @"(空)",
            host.localAddress);
        existingHost.localAddress = host.localAddress;
    }
    if (host.ipv6Address.length > 0 && ![host.ipv6Address isEqualToString:existingHost.ipv6Address]) {
        existingHost.ipv6Address = host.ipv6Address;
    }
    // externalAddress 可能来自本机的 STUN 推断结果，这里保留原来的「只填空位」策略
    if (host.externalAddress.length > 0 && existingHost.externalAddress.length == 0) {
        existingHost.externalAddress = host.externalAddress;
    }
    if (host.mac.length > 0 && existingHost.mac.length == 0) {
        existingHost.mac = host.mac;
    }
    if (host.serverCert != nil && existingHost.serverCert == nil) {
        existingHost.serverCert = host.serverCert;
    }

    // 可用地址以最新发现为准，避免继续把请求打到已经失效的 activeAddress 上
    if (host.activeAddress.length > 0) {
        existingHost.activeAddress = host.activeAddress;
    }

    // UUID 缺失的临时主机探测失败时不要把已有状态降级，避免误报离线
    if (updateState) {
        existingHost.state = host.state;
    } else if (host.state == StateOnline) {
        existingHost.state = StateOnline;
    }
}

- (BOOL) addHostToDiscovery:(TemporaryHost *)host {
    if (host.uuid.length == 0) {
        // mDNS 发现的主机在 serverinfo 成功之前没有 UUID，先尝试按地址 / 主机名归并到已有记录，
        // 否则这台主机的新地址永远无法进入记录，探测会一直打在过期地址上。
        TemporaryHost *matchedHost = [self getHostInDiscoveryByAddressOrName:host];
        if (matchedHost != nil) {
            Log(LOG_I, @"按地址 / 主机名归并 mDNS 发现的主机：%@", host.name ?: @"");
            [self mergeDiscoveredHost:host intoExistingHost:matchedHost updateState:NO];
        }
        return NO;
    }
    
    TemporaryHost *existingHost = [self getHostInDiscovery:host.uuid];
    if (existingHost != nil) {
        [self mergeDiscoveredHost:host intoExistingHost:existingHost updateState:YES];
        return NO;
    }
    else {
        @synchronized (_hostQueue) {
            [_hostQueue addObject:host];
            if (shouldDiscover) {
                [_opQueue addOperation:[self createWorkerForHost:host]];
            }
        }
        return YES;
    }
}

- (void) removeHostFromDiscovery:(TemporaryHost *)host {
    @synchronized (_hostQueue) {
        for (DiscoveryWorker* worker in [_opQueue operations]) {
            if ([worker getHost] == host) {
                [worker cancel];
            }
        }
        
        [_hostQueue removeObject:host];
        [_pausedHosts removeObject:host];
    }
}

- (void) pauseDiscoveryForHost:(TemporaryHost *)host {
    @synchronized (_hostQueue) {
        // Stop any worker for the host
        for (DiscoveryWorker* worker in [_opQueue operations]) {
            if ([worker getHost] == host) {
                [worker cancel];
            }
        }
        
        // Add it to the paused hosts list
        [_pausedHosts addObject:host];
    }
}

- (void) resumeDiscoveryForHost:(TemporaryHost *)host {
    @synchronized (_hostQueue) {
        // Remove it from the paused hosts list
        [_pausedHosts removeObject:host];
        
        // Start discovery again
        if (shouldDiscover) {
            [_opQueue addOperation:[self createWorkerForHost:host]];
        }
    }
}

// Override from MDNSCallback - called in a worker thread
- (void)updateHost:(TemporaryHost*)host {
    // Discover the hosts before adding to eliminate duplicates
    Log(LOG_D, @"Found host through MDNS: %@:", host.name);
    // Since this is on a background thread, we do not need to use the opQueue
    DiscoveryWorker* worker = (DiscoveryWorker*)[self createWorkerForHost:host];
    [worker discoverHost];
    TemporaryHost *knownHost = [self getHostInDiscovery:host.uuid];
    if (knownHost == nil && !MoonlightShouldAutoDiscoverNewHosts()) {
        Log(LOG_I, @"Ignoring newly discovered host because automatic discovery is disabled: %@", host.name ?: @"");
        return;
    }
    if ([self addHostToDiscovery:host]) {
        Log(LOG_I, @"Found new host through MDNS: %@:", host.name);
        @synchronized (_hostQueue) {
            [_callback updateAllHosts:_hostQueue];
        }
    } else {
        Log(LOG_D, @"Found existing host through MDNS: %@", host.name);
    }
}

- (TemporaryHost*) getHostInDiscovery:(NSString*)uuidString {
    @synchronized (_hostQueue) {
        for (TemporaryHost* discoveredHost in _hostQueue) {
            if (discoveredHost.uuid.length > 0 && [discoveredHost.uuid isEqualToString:uuidString]) {
                return discoveredHost;
            }
        }
    }
    return nil;
}

- (NSOperation*) createWorkerForHost:(TemporaryHost*)host {
    DiscoveryWorker* worker = [[DiscoveryWorker alloc] initWithHost:host uniqueId:_uniqueId];
    return worker;
}

@end
