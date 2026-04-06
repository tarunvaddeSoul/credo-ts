export interface GroupMessagingModuleConfigOptions {
  /**
   * Maximum seconds between automatic key rotations.
   * @default 604800 (7 days)
   */
  rotationPeriodSeconds?: number

  /**
   * Maximum group messages between automatic key rotations.
   * @default 100
   */
  rotationPeriodMessages?: number
}

export class GroupMessagingModuleConfig {
  private options: GroupMessagingModuleConfigOptions

  public constructor(options?: GroupMessagingModuleConfigOptions) {
    this.options = options ?? {}
  }

  public get rotationPeriodSeconds(): number {
    return this.options.rotationPeriodSeconds ?? 604800
  }

  public get rotationPeriodMessages(): number {
    return this.options.rotationPeriodMessages ?? 100
  }
}
