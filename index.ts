import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { MoopsyError } from '@moopsyjs/core';
import type { Collection, Db } from 'mongodb';

const DEFAULT_LOGIN_TOKEN_BYTES = 24;
const DEFAULT_LOGIN_TOKEN_TTL_HOURS = 24 * 365;

export interface AuthKitHashedString {
    digest: string,
    algorithm: string,
};

export interface AuthKitLoginTokensCollectionEntry {
  userId: string,
  hashedToken: string,
  issued: Date,
}

export interface AuthKitPasswordsCollectionEntry {
  userId: string,
  bcrypt: string,
  updated: Date,
  updateReason: string,
}

export interface AuthKitConfigType {
  collectionNameSuffix: string;
  loginTokenBytes: number;
  loginTokenTTLHours: number;
}

export class AuthKit {
  private loginTokensCollection: Collection<AuthKitLoginTokensCollectionEntry>;
  private passwordsCollection: Collection<AuthKitPasswordsCollectionEntry>;
  private loginTokenBytes: number;
  private loginTokenTTLHours: number;

  static sha256 (data: string): AuthKitHashedString {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return { digest: hash.digest('hex'), algorithm: "sha-256" };
  }

  constructor(private database: Db, private config?: Partial<AuthKitConfigType>) {
    this.loginTokensCollection = this.database.collection(`authkitloginTokens${config?.collectionNameSuffix ?? ""}`);
    this.passwordsCollection = this.database.collection(`authkitpasswords${config?.collectionNameSuffix ?? ""}`);
    this.loginTokenBytes = config?.loginTokenBytes ?? DEFAULT_LOGIN_TOKEN_BYTES;
    this.loginTokenTTLHours = config?.loginTokenTTLHours ?? DEFAULT_LOGIN_TOKEN_TTL_HOURS;
  }

  /**
   * Validates that the correct password is provided for the specified user.
   * Will throw a 403 coded MoopsyError if the password is incorrect
   */
  public readonly validateUserPassword = async ({ userId, password }:{ userId: string, password: AuthKitHashedString }): Promise<void> => {
    const passwordEntry = await this.passwordsCollection.findOne({ userId });

    if(passwordEntry == null) {
      throw new MoopsyError(404, '404');
    }
    
    const passwordHash: string = passwordEntry.bcrypt;
    
    const match = await bcrypt.compare(password.digest, passwordHash);

    if (!match) {
      throw new MoopsyError(403, 'incorrect-password', 'Incorrect Password');
    }
  }

  /**
   * Generates and saves a new login token for the specified user
   */
  public readonly generateLoginTokenForUser = async ({ userId }:{ userId: string }): Promise<{ plainToken: string, entry: AuthKitLoginTokensCollectionEntry }> => {
    const plainToken = crypto.randomBytes(this.loginTokenBytes).toString('hex');
    const hashedToken = AuthKit.sha256(plainToken).digest;

    const entry: AuthKitLoginTokensCollectionEntry = {
      userId,
      hashedToken,
      issued: new Date(),
    };

    await this.loginTokensCollection.insertOne(entry);

    return {
      entry,
      plainToken
    };
  }

  /**
   * Invalidates all login tokens for a user
   */
  public readonly dropAllLoginTokens = async ({ userId }:{ userId: string }) => {
    await this.loginTokensCollection.deleteMany({ userId });
  }

  /**
   * Drops a specific login token, like for when a user logs out
   */
  public readonly dropToken = async ({ plainToken }:{ plainToken: string }) => {
    const hashedToken = AuthKit.sha256(plainToken).digest;
    await this.loginTokensCollection.deleteOne({ hashedToken });
  }


  /**
   * Accepts an unverified userId and password, validates the credentials are accurate, and returns a login token.
   * Will throw a 403 coded MoopsyError if the password is incorrect
   */
  public readonly loginUserWithUserIdAndPassword = async ({ userId, password }:{ userId: string, password: AuthKitHashedString }): Promise<{ plainToken: string }> => {
    await this.validateUserPassword({ userId, password });

    const { plainToken } = await this.generateLoginTokenForUser({ userId });

    return { plainToken };
  }

  /**
   * Sets a user password. Will succeed whether a password has or has not already been set, so can be used on user creation
   */
  public readonly setUserPassword = async ({ userId, password, updateReason, invalidateLoginTokens }:{ userId: string, password: AuthKitHashedString, updateReason: string, invalidateLoginTokens: boolean }) => {
    const bcryptValue = await bcrypt.hash(typeof password !== "string" ? password.digest : await AuthKit.sha256(password).digest, 10);

    await this.passwordsCollection.updateOne(
      { userId },
      {
        $set: {
          bcrypt: bcryptValue,
          updated: new Date(),
          updateReason,
          userId
        }
      },
      { upsert: true }
    );

    if(invalidateLoginTokens) {
        await this.dropAllLoginTokens({ userId });
    }
  }

  /**
   * Checks a login token. Will throw a 404 error if the token is not found or if the token is expired.
   * If valid, returns the associated userId and the expiration date of the token
   */
  public readonly checkLoginToken = async ({ token }:{ token: string; }): Promise<{ userId: string, expires: Date; }> => {
    const hashedToken = AuthKit.sha256(token).digest;

    const entry = await this.loginTokensCollection.findOne({ hashedToken });

    if(entry == null) {
      throw new MoopsyError(404, '404');
    }

    const expires = new Date(entry.issued.valueOf() + (1000 * 60 * 60 * this.loginTokenTTLHours));

    if(expires < new Date()) {
      await this.dropToken({ plainToken: token });
      throw new MoopsyError(404, '404');
    }

    return { userId: entry.userId, expires };
  }
}