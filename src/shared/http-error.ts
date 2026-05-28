export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string
  ) {
    super(message);
  }
}

export function badRequest(code: string, message: string): never {
  throw new HttpError(400, code, message);
}

export function unauthorized(code: string, message: string): never {
  throw new HttpError(401, code, message);
}

export function forbidden(code: string, message: string): never {
  throw new HttpError(403, code, message);
}

export function notFound(code: string, message: string): never {
  throw new HttpError(404, code, message);
}
