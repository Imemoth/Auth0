import argon2 from 'argon2';
import { badRequest } from '../shared/http-error.js';

export class PasswordHasher {
  async hash(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1
    });
  }

  async verify(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }
}

export class PasswordPolicy {
  constructor(private readonly minLength: number) {}

  assertValid(password: string): void {
    if (password.length < this.minLength) {
      badRequest('PASSWORD_TOO_SHORT', `Password must be at least ${this.minLength} characters long.`);
    }
    if (password.length > 256) {
      badRequest('PASSWORD_TOO_LONG', 'Password is too long.');
    }
    if (/^\s|\s$/.test(password)) {
      badRequest('PASSWORD_HAS_EDGE_WHITESPACE', 'Password cannot start or end with whitespace.');
    }
  }
}
