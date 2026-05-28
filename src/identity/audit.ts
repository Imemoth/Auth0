import { randomId } from '../shared/crypto.js';
import type { AuditEvent, AuditSeverity, RequestContext } from './types.js';
import { InMemoryIdentityStore } from './store.js';

export class AuditLogger {
  constructor(private readonly store: InMemoryIdentityStore) {}

  write(input: {
    type: string;
    userId?: string;
    severity?: AuditSeverity;
    message: string;
    metadata?: Record<string, unknown>;
    context?: RequestContext;
  }): AuditEvent {
    const event: AuditEvent = {
      id: randomId('aud'),
      type: input.type,
      userId: input.userId,
      severity: input.severity ?? 'INFO',
      message: input.message,
      metadata: input.metadata,
      ipAddress: input.context?.ipAddress,
      userAgent: input.context?.userAgent,
      createdAt: new Date()
    };
    this.store.auditEvents.push(event);
    return event;
  }
}
