import * as jose from 'jose';
import { createSecretKey } from 'crypto';
import {
  KredsAuthenticationOutcome,
  KredsStoreFunction,
  KredsStrategy,
  KredsStrategyOptions,
  KredsVerifyUserFunction,KredsContext
} from '@kreds/types';

interface JWTStrategyOptions<TUser> extends KredsStrategyOptions<TUser> {
  keyType?: string;

  /**
   * Base64 encoded key.
   */
  key: string;
  expiry: number;

  verify: KredsVerifyUserFunction<TUser, jose.JWTDecryptResult>;
  store?: KredsStoreFunction<TUser, jose.JWTPayload>;
}

export class JWTStrategy<TUser> implements KredsStrategy<TUser> {
  name = 'jwt';
  private key: jose.KeyLike;

  constructor(private options: JWTStrategyOptions<TUser>) {
    if (options.store) {
      this.store = this.store!.bind(this);
    } else {
      this.store = undefined;
    }

    this.key = createSecretKey(Buffer.from(options.key, 'base64'));
  }

  async authenticate(
    context: KredsContext
  ): Promise<KredsAuthenticationOutcome<TUser> | undefined> {
    let token: string | undefined;

    if (context.transport === 'http') {
      const authorization = context.adapter.getAuthorization();
      if (
        !authorization ||
        !authorization.credentials ||
        authorization.type !== 'JWT'
      ) {
        return undefined;
      }
      token = authorization.credentials;
    } else if (context.transport === 'authenticate_function') {
      if (typeof context.payload !== 'string') {
        return undefined;
      }

      token = context.payload;
    } else {
      return undefined;
    }

    try {
      const jwt = await jose.jwtDecrypt(token, this.key);
      return await this.options.verify(context, jwt);
    } catch {
      return undefined;
    }
  }

  async store?(context: KredsContext, user: TUser): Promise<void> {
    const jwt = await new jose.EncryptJWT(
      await this.options.store!(context, user)
    )
      .setProtectedHeader({ alg: 'dir', enc: 'A128CBC-HS256' })
      .setIssuedAt()
      .setExpirationTime(this.options.expiry + 's')
      .encrypt(this.key);
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + this.options.expiry);
    context.authorization = {
      type: 'JWT',
      credentials: jwt,
      expiresAt: expiresAt.getTime(),
    };
  }
}
