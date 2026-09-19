//
//  DataManager.m
//  Moonlight
//
//  Created by Diego Waxemberg on 10/28/14.
//  Copyright (c) 2014 Moonlight Stream. All rights reserved.
//

#import "DataManager.h"
#import "TemporaryApp.h"
#import "TemporarySettings.h"
#import "DatabaseSingleton.h"

@implementation DataManager {
    NSManagedObjectContext *_managedObjectContext;
}

- (id) init {
    self = [super init];
    
    _managedObjectContext = [[NSManagedObjectContext alloc] initWithConcurrencyType:NSPrivateQueueConcurrencyType];
    [_managedObjectContext setPersistentStoreCoordinator:[DatabaseSingleton shared].persistentStoreCoordinator];
    [_managedObjectContext setMergePolicy:NSMergeByPropertyObjectTrumpMergePolicy];
    
    return self;
}

- (void) updateUniqueId:(NSString*)uniqueId {
    [_managedObjectContext performBlockAndWait:^{
        [self retrieveSettings].uniqueId = uniqueId;
        [self saveData];
    }];
}

- (NSString*) getUniqueId {
    __block NSString *uid;
    
    [_managedObjectContext performBlockAndWait:^{
        uid = [self retrieveSettings].uniqueId;
    }];

    return uid;
}

- (void) saveSettingsWithBitrate:(NSInteger)bitrate
                       framerate:(NSInteger)framerate
                          height:(NSInteger)height
                           width:(NSInteger)width
                onscreenControls:(NSInteger)onscreenControls
                          remote:(BOOL)streamingRemotely
                   optimizeGames:(BOOL)optimizeGames
                 multiController:(BOOL)multiController
                       audioOnPC:(BOOL)audioOnPC
                         useHevc:(BOOL)useHevc
                       enableHdr:(BOOL)enableHdr
                  btMouseSupport:(BOOL)btMouseSupport {
    
    [_managedObjectContext performBlockAndWait:^{
        Settings* settingsToSave = [self retrieveSettings];
        settingsToSave.framerate = [NSNumber numberWithInteger:framerate];
        settingsToSave.bitrate = [NSNumber numberWithInteger:bitrate];
        settingsToSave.height = [NSNumber numberWithInteger:height];
        settingsToSave.width = [NSNumber numberWithInteger:width];
        settingsToSave.onscreenControls = [NSNumber numberWithInteger:onscreenControls];
        settingsToSave.streamingRemotely = streamingRemotely;
        settingsToSave.optimizeGames = optimizeGames;
        settingsToSave.multiController = multiController;
        settingsToSave.playAudioOnPC = audioOnPC;
        settingsToSave.useHevc = useHevc;
        settingsToSave.enableHdr = enableHdr;
        settingsToSave.btMouseSupport = btMouseSupport;
        
        [self saveData];
    }];
}

- (void) updateHost:(TemporaryHost *)host {
    [_managedObjectContext performBlockAndWait:^{
        // Add a new persistent managed object if one doesn't exist
        Host* parent = [self getHostForTemporaryHost:host withHostRecords:[self fetchRecords:@"Host"]];
        if (parent == nil) {
            // 没有 UUID 且匹配不到已有记录时不要新建记录：这类对象通常是 mDNS 刚发现的
            // 临时主机，写进去只会产生无 UUID 的空壳记录并被清理逻辑反复删除，污染数据库。
            if (host.uuid.length == 0) {
                return;
            }

            NSEntityDescription* entity = [NSEntityDescription entityForName:@"Host" inManagedObjectContext:self->_managedObjectContext];
            parent = [[Host alloc] initWithEntity:entity insertIntoManagedObjectContext:self->_managedObjectContext];
        }
        
        // Push changes from the temp host to the persistent one
        [host propagateChangesToParent:parent];
        
        [self saveData];
    }];
}

- (void) updateAppsForExistingHost:(TemporaryHost *)host {
    [_managedObjectContext performBlockAndWait:^{
        Host* parent = [self getHostForTemporaryHost:host withHostRecords:[self fetchRecords:@"Host"]];
        if (parent == nil) {
            // The host must exist to be updated
            return;
        }
        
        NSMutableSet *applist = [[NSMutableSet alloc] init];
        NSArray *appRecords = [self fetchRecords:@"App"];
        for (TemporaryApp* app in host.appList) {
            // Add a new persistent managed object if one doesn't exist
            App* parentApp = [self getAppForTemporaryApp:app withAppRecords:appRecords];
            if (parentApp == nil) {
                NSEntityDescription* entity = [NSEntityDescription entityForName:@"App" inManagedObjectContext:self->_managedObjectContext];
                parentApp = [[App alloc] initWithEntity:entity insertIntoManagedObjectContext:self->_managedObjectContext];
            }
            
            [app propagateChangesToParent:parentApp withHost:parent];
            
            [applist addObject:parentApp];
        }
        
        parent.appList = applist;
        
        [self saveData];
    }];
}

- (TemporarySettings*) getSettings {
    __block TemporarySettings *tempSettings;
    
    [_managedObjectContext performBlockAndWait:^{
        tempSettings = [[TemporarySettings alloc] initFromSettings:[self retrieveSettings]];
    }];
    
    return tempSettings;
}

- (Settings*) retrieveSettings {
    NSArray* fetchedRecords = [self fetchRecords:@"Settings"];
    if (fetchedRecords.count == 0) {
        // create a new settings object with the default values
        NSEntityDescription* entity = [NSEntityDescription entityForName:@"Settings" inManagedObjectContext:_managedObjectContext];
        Settings* settings = [[Settings alloc] initWithEntity:entity insertIntoManagedObjectContext:_managedObjectContext];
        
        return settings;
    } else {
        // we should only ever have 1 settings object stored
        return [fetchedRecords objectAtIndex:0];
    }
}

- (void) removeApp:(TemporaryApp*)app {
    [_managedObjectContext performBlockAndWait:^{
        App* managedApp = [self getAppForTemporaryApp:app withAppRecords:[self fetchRecords:@"App"]];
        if (managedApp != nil) {
            [self->_managedObjectContext deleteObject:managedApp];
            [self saveData];
        }
    }];
}

- (void) removeHost:(TemporaryHost*)host {
    [_managedObjectContext performBlockAndWait:^{
        Host* managedHost = [self getHostForTemporaryHost:host withHostRecords:[self fetchRecords:@"Host"]];
        if (managedHost != nil) {
            [self->_managedObjectContext deleteObject:managedHost];
            [self saveData];
        }
    }];
}

- (void) saveData {
    NSError* error;
    if ([_managedObjectContext hasChanges] && ![_managedObjectContext save:&error]) {
        Log(LOG_E, @"Unable to save hosts to database: %@", error);
    }

    [[DatabaseSingleton shared] saveContext];
}

- (NSArray*) getHosts {
    __block NSMutableArray *tempHosts = [[NSMutableArray alloc] init];
    
    [_managedObjectContext performBlockAndWait:^{
        NSArray *hosts = [self fetchRecords:@"Host"];
        
        for (Host* host in hosts) {
            [tempHosts addObject:[[TemporaryHost alloc] initFromHost:host]];
        }
    }];
    
    return tempHosts;
}

- (void) removeHostsWithEmptyUuid {
    [_managedObjectContext performBlockAndWait:^{
        NSArray *hosts = [self fetchRecords:@"Host"];
        BOOL didDelete = NO;
        for (id host in hosts) {
            NSString *uuid = [host valueForKey:@"uuid"];
            if (uuid == nil || uuid.length == 0) {
                [self->_managedObjectContext deleteObject:host];
                didDelete = YES;
            }
        }
        if (didDelete) {
            [self saveData];
        }
    }];
}

// Only call from within performBlockAndWait!!!
- (Host*) getHostForTemporaryHost:(TemporaryHost*)tempHost withHostRecords:(NSArray*)hosts {
    for (Host* host in hosts) {
        if (tempHost.uuid != nil && [tempHost.uuid isEqualToString:host.uuid]) {
            return host;
        }
    }

    // Fallback matching when UUID is missing
    if (tempHost.uuid == nil || tempHost.uuid.length == 0) {
        for (Host* host in hosts) {
            if (tempHost.mac != nil && host.mac != nil && [tempHost.mac isEqualToString:host.mac]) {
                return host;
            }
            if (tempHost.address != nil && host.address != nil && [tempHost.address isEqualToString:host.address]) {
                return host;
            }
            // 名称匹配排除 mDNS 的 .local. 临时主机名：它与记录里的正式主机名不同源，
            // 用它匹配会把「同一台主机的两条记录」错误地合并到一起。
            if (tempHost.name.length > 0 && host.name.length > 0 &&
                ![tempHost.name hasSuffix:@".local."] &&
                [tempHost.name isEqualToString:host.name]) {
                return host;
            }
        }
    }
    
    return nil;
}

// Only call from within performBlockAndWait!!!
- (App*) getAppForTemporaryApp:(TemporaryApp*)tempApp withAppRecords:(NSArray*)apps {
    for (App* app in apps) {
        if ([app.id isEqualToString:tempApp.id] &&
            [app.host.uuid isEqualToString:tempApp.host.uuid]) {
            return app;
        }
    }
    
    return nil;
}

- (NSArray*) fetchRecords:(NSString*)entityName {
    NSArray* fetchedRecords;
    
    NSFetchRequest* fetchRequest = [[NSFetchRequest alloc] init];
    NSEntityDescription* entity = [NSEntityDescription entityForName:entityName inManagedObjectContext:_managedObjectContext];
    [fetchRequest setEntity:entity];
    
    NSError* error;
    fetchedRecords = [_managedObjectContext executeFetchRequest:fetchRequest error:&error];
    //TODO: handle errors
    
    return fetchedRecords;
}

@end

