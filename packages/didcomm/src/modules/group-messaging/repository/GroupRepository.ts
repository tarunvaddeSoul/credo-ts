import { EventEmitter, InjectionSymbols, inject, injectable, Repository, type StorageService } from '@credo-ts/core'

import { GroupRecord } from './GroupRecord'

@injectable()
export class GroupRepository extends Repository<GroupRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<GroupRecord>,
    eventEmitter: EventEmitter
  ) {
    super(GroupRecord, storageService, eventEmitter)
  }
}
