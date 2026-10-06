import {
  parsePhoneNumberFromString,
  type CountryCode,
} from 'libphonenumber-js/max';

import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';

export function normalizePhone(input: string): string {
  const parsed = parsePhoneNumberFromString(
    input,
    env.PHONE_DEFAULT_COUNTRY.toUpperCase() as CountryCode,
  );

  if (!parsed?.isValid()) {
    throw new AppError(400, 'INVALID_PHONE');
  }

  return parsed.number;
}

