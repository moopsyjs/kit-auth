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

export interface AuthKitHistoricPasswordsCollectionEntry {
  userId: string,
  bcrypt: string,
  date: Date,
  version: number,
}

export interface AuthKitConfigType {
  collectionNameSuffix: string;
  loginTokenBytes: number;
  loginTokenTTLHours: number;
  /**
   * Allow calling the dangerous_getPasswordRecord method
   */
  allowPasswordExport: boolean;

  /**
   * If true, passwords cannot be reused
   */
  preventPasswordReuse: boolean;
  /**
   * If preventPasswordReuse is true, this is the number of days that must pass before a password can be reused.
   * 
   * Default: 365
   */
  passwordReuseTimeLimit: number;
  /**
   * If preventPasswordReuse is true, this is the number of versions of a password that are stored.
   * 
   * Default: 5
   */
  passwordReuseVersions: number;
}

export class AuthKit {
  private loginTokensCollection: Collection<AuthKitLoginTokensCollectionEntry>;
  private passwordsCollection: Collection<AuthKitPasswordsCollectionEntry>;
  private historicPasswordsCollection: Collection<AuthKitHistoricPasswordsCollectionEntry>;
  private loginTokenBytes: number;
  private loginTokenTTLHours: number;
  private passwordReuseVersions: number;
  private passwordReuseTimeLimit: number;
  private preventPasswordReuse: boolean;

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
    this.preventPasswordReuse = config?.preventPasswordReuse ?? false;
    this.passwordReuseVersions ?? config?.passwordReuseVersions ?? 5
    this.passwordReuseTimeLimit ?? config?.passwordReuseTimeLimit ?? 365;
  }

  /**
   * Checks that the correct password is provided for the specified user.
   * 
   * Returns `true` for correct, `false` for incorrect
   */
  public readonly checkUserPassword = async ({ userId, password }:{ userId: string, password: AuthKitHashedString }): Promise<boolean> => {
    const passwordEntry = await this.passwordsCollection.findOne({ userId });

    if(passwordEntry == null) {
      throw new MoopsyError(404, "No password saved for user");
    }
    
    const passwordHash: string = passwordEntry.bcrypt;
    
    const match = await bcrypt.compare(password.digest, passwordHash);

    return match;
  }

  /**
   * Validates that the correct password is provided for the specified user.
   * Will throw a 403 coded MoopsyError if the password is incorrect
   */
  public readonly validateUserPassword = async ({ userId, password }:{ userId: string, password: AuthKitHashedString }): Promise<void> => {    
    const match = await this.checkUserPassword({ userId, password });

    if (!match) {
      throw new MoopsyError(403, "Incorrect Password");
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
    const bcryptValue: string = await bcrypt.hash(typeof password !== "string" ? password.digest : await AuthKit.sha256(password).digest, 10);

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

    if(this.preventPasswordReuse === true) {
      const historicPasswords = await this.historicPasswordsCollection.find({
        userId,
      }, { sort: { date: -1 } }).toArray();

      for(const historicPassword of historicPasswords) {
        const match: boolean = await bcrypt.compare(password.digest, historicPassword.bcrypt);

        if(match) {
          throw new MoopsyError(400, "Password has been used before");
        }
      }
      
      const version = historicPasswords[0]?.version ?? 0;

      await this.historicPasswordsCollection.insertOne({
        userId,
        bcrypt: bcryptValue,
        date: new Date(),
        version: version + 1
      });

      await this.historicPasswordsCollection.deleteMany({
        $and: [
          { userId },
          { version: { $lt: version - this.passwordReuseVersions }},
        ]
      });
    }

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
      throw new MoopsyError(404, "No login token found");
    }

    const expires = new Date(entry.issued.valueOf() + (1000 * 60 * 60 * this.loginTokenTTLHours));

    if(expires < new Date()) {
      await this.dropToken({ plainToken: token });
      throw new MoopsyError(404, "No login token found");
    }

    return { userId: entry.userId, expires };
  }
}