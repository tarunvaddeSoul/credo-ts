import { EventEmitter, InjectionSymbols, inject, injectable, Repository, type StorageService } from '@credo-ts/core'

import { GroupMessageRecord } from './GroupMessageRecord'

@injectable()
export class GroupMessageRepository extends Repository<GroupMessageRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<GroupMessageRecord>,
    eventEmitter: EventEmitter
  ) {
    super(GroupMessageRecord, storageService, eventEmitter)
  }
}
