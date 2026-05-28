import 'dotenv/config';
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  JWT_ISSUER: z.string().default('http://localhost:4000'),
  JWT_AUDIENCE: z.string().default('financial-api'),
  JWT_ACCESS_TOKEN_SECRET: z.string().min(32).default('development-only-secret-change-before-production-000000000000'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(14),
  SESSION_ABSOLUTE_TIMEOUT_HOURS: z.coerce.number().int().positive().default(12),
  PASSWORD_MIN_LENGTH: z.coerce.number().int().positive().default(12)
});

export function loadConfig() {
  const env = EnvSchema.parse(process.env);
  return {
    nodeEnv: env.NODE_ENV,
    port: env.PORT,
    jwt: {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      accessTokenSecret: env.JWT_ACCESS_TOKEN_SECRET,
      accessTokenTtlSeconds: env.ACCESS_TOKEN_TTL_SECONDS
    },
    refreshTokenTtlDays: env.REFRESH_TOKEN_TTL_DAYS,
    sessionAbsoluteTimeoutHours: env.SESSION_ABSOLUTE_TIMEOUT_HOURS,
    passwordMinLength: env.PASSWORD_MIN_LENGTH
  };
}

export type AppConfig = ReturnType<typeof loadConfig>;
