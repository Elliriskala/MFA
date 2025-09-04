import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {TokenContent, User, UserWithLevel} from '@sharedTypes/DBTypes';
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import fetchData from '../../utils/fetchData';
import OTPAuth from 'otpauth';
import twoFAModel from '../models/twoFAModel';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';

const setupTwoFA = async (
  req: Request<{}, {}, User>,
  res: Response<{qrCodeUrl: string}>,
  next: NextFunction,
) => {
  try {
    // Register user to AUTH API
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };

    const userResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );
    console.log(userResponse);

    // Generate a new 2FA secret
    const secret = new OTPAuth.Secret();

    // Create the TOTP instance
    const totp = new OTPAuth.TOTP({
      issuer: 'ElukkaAPi',
      label: userResponse.user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secret,
    });

    // Store the 2FA data in the database
    await twoFAModel.create({
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      twoFactorEnabled: true,
      twoFactorSecret: secret.base32,
    });

    // Generate a QR code and send it in the response
    const imageUrl = await QRCode.toDataURL(totp.toString());
    res.json({qrCodeUrl: imageUrl});
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Define verifyTwoFA function
const verifyTwoFA = async (
  req: Request<{}, {}, {email: string; code: string}>,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  const {email, code} = req.body;

  try {
    // Retrieve 2FA data from the database
    const twoFactorData = await twoFAModel.findOne({email});
    if (!twoFactorData) {
      next(new CustomError('2FA not enabled', 400));
      return;
    }
    // Validate the 2FA code
    const totp = new OTPAuth.TOTP({
      issuer: 'ElukkaApi',
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(twoFactorData.twoFactorSecret),
    });
    const isValid = totp.validate({token: code, window: 1});
    if (isValid === null) {
      next(new CustomError('Verification code is not valid', 400));
      return;
    }
    // If valid, get the user from AUTH API
    const userResponse = await fetchData<UserWithLevel>(
      `${process.env.AUTH_URL}/api/v1/users/${twoFactorData.userId}`,
    );
    if (!userResponse) {
      next(new CustomError('User not found', 401));
    }
    // Create and return a JWT token
    const tokenContent: TokenContent = {
      user_id: userResponse.user_id,
      level_name: userResponse.level_name,
    };

    if (!process.env.JWT_SECRET) {
      next(new CustomError('JWT not set', 500));
      return;
    }
    const token = jwt.sign(tokenContent, process.env.JWT_SECRET);
    const loginResponse: LoginResponse = {
      user: userResponse,
      token,
      message: 'Login Success',
    };

    res.json(loginResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
