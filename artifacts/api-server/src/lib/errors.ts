export class HttpError extends Error {
  constructor(
    public statusCode: number,
    public code: string,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class NotFoundError extends HttpError {
  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(404, code, message, details);
  }
}

export class BadRequestError extends HttpError {
  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(400, code, message, details);
  }
}

export class PayloadTooLargeError extends HttpError {
  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(413, code, message, details);
  }
}
