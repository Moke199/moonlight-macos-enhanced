//
//  SettingsModel.swift
//  Moonlight SwiftUI
//
//  Created by Michael Kenny on 25/1/2023.
//  Copyright © 2023 Moonlight Game Streaming Project. All rights reserved.
//

import AppKit
import CoreGraphics
import SwiftUI
import VideoToolbox

extension SettingsModel {
  var streamRiskAssessment: StreamRiskAssessment {
    let mode = effectiveStreamingModeForRiskAssessment()
    let bitrateKbps = effectiveBitrateKbpsForRiskAssessment(
      width: mode.width,
      height: mode.height,
      fps: mode.fps
    )
    return StreamRiskAssessor.assess(
      host: selectedTemporaryHostForRiskAssessment(),
      targetAddress: nil,
      connectionMethod: selectedConnectionMethod,
      width: mode.width,
      height: mode.height,
      fps: mode.fps,
      bitrateKbps: bitrateKbps,
      codecName: selectedVideoCodec,
      enableYUV444: enableYUV444,
      autoMode: autoAdjustBitrate
    )
  }

  private func selectedTemporaryHostForRiskAssessment() -> TemporaryHost? {
    guard let hostId = selectedHost?.id, hostId != Self.globalHostId else {
      return nil
    }

    let dataManager = DataManager()
    guard let hosts = dataManager.getHosts() as? [TemporaryHost] else {
      return nil
    }

    return hosts.first(where: { !$0.uuid.isEmpty && $0.uuid == hostId })
  }

  private func effectiveStreamingModeForRiskAssessment() -> (width: Int, height: Int, fps: Int) {
    var resolution = effectiveResolutionForBitrate()

    if streamResolutionScale,
      streamResolutionScaleRatio > 0,
      streamResolutionScaleRatio != 100
    {
      let scaledWidth =
        Self.safeInt(resolution.width, clampedTo: Self.customResolutionRange)
        * streamResolutionScaleRatio / 100
      let scaledHeight =
        Self.safeInt(resolution.height, clampedTo: Self.customResolutionRange)
        * streamResolutionScaleRatio / 100
      resolution = CGSize(
        width: CGFloat((scaledWidth / 8) * 8),
        height: CGFloat((scaledHeight / 8) * 8)
      )
    }

    var width = max(2, Self.safeInt(resolution.width, clampedTo: Self.customResolutionRange))
    var height = max(2, Self.safeInt(resolution.height, clampedTo: Self.customResolutionRange))
    var fps = max(1, effectiveFpsForBitrate())

    if remoteResolutionEnabled {
      if selectedRemoteResolution == .zero {
        if let remoteCustomResWidth, let remoteCustomResHeight,
          remoteCustomResWidth > 0, remoteCustomResHeight > 0
        {
          width = Self.safeInt(remoteCustomResWidth, clampedTo: Self.customResolutionRange)
          height = Self.safeInt(remoteCustomResHeight, clampedTo: Self.customResolutionRange)
        }
      } else {
        width = Int(selectedRemoteResolution.width)
        height = Int(selectedRemoteResolution.height)
      }
    }

    if remoteFpsEnabled {
      if selectedRemoteFps == .zero {
        if let remoteCustomFps, remoteCustomFps > 0 {
          fps = Self.safeInt(remoteCustomFps, clampedTo: Self.customFpsRange)
        }
      } else {
        fps = selectedRemoteFps
      }
    }

    width &= ~1
    height &= ~1

    return (max(2, width), max(2, height), max(1, fps))
  }

  private func effectiveBitrateKbpsForRiskAssessment(width: Int, height: Int, fps: Int) -> Int {
    if autoAdjustBitrate {
      return Self.getDefaultBitrateKbps(
        width: width,
        height: height,
        fps: fps,
        yuv444: enableYUV444
      )
    }

    let steps = Self.bitrateSteps(unlocked: unlockMaxBitrate)
    let index = max(0, min(Int(bitrateSliderValue), steps.count - 1))
    return customBitrate ?? Int(steps[index] * 1000.0)
  }
}
