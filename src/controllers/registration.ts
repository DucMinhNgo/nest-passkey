import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { base64ToUint8Array, uint8ArrayToBase64 } from '../utils/utils';
import { rpName, rpID, origin } from '../utils/constants';
import { credentialService } from '../services/credentialService';
import { userService } from '../services/userService'
import { RegistrationResponseJSON } from "@simplewebauthn/typescript-types";
import { Request, Response, NextFunction } from 'express';
import { CustomError } from '../middleware/customError';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

// const parser = require('ua-parser-js');
import { UAParser } from 'ua-parser-js';
import { VerifiedAuthenticationResponse, VerifyAuthenticationResponseOpts } from "@simplewebauthn/server/esm";

// import * as SimpleWebAuthnBrowser from '@simplewebauthn/browser';



export const handleRegisterStart = async (req: Request, res: Response, next: NextFunction) => {
    const { username } = req.body;
    const { currentChallenge } = req.session;

    console.log(req.headers['user-agent'])
    const ua = UAParser(req.headers['user-agent']);
    console.log(ua);
    console.log(JSON.stringify(ua, null, '  '));

    console.log(`${ua.os.name} ${ua.os.version}`);
    // if (!currentChallenge) {
    //     return next(new CustomError('Current challenge is missing', 400));
    // }

    if (!username) {
        return next(new CustomError('Username empty', 400));
    }

    // try {
    let user = await userService.getUserByUsername(username);
    if (user) {
        // return next(new CustomError('User already exists', 400));
    } else {
        user = await userService.createUser(username);
    }

    console.log(user);


    console.log({
        rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        timeout: 60000,
        attestationType: 'direct',
        excludeCredentials: [],
        authenticatorSelection: {
            residentKey: 'preferred',
        },
        // Support for the two most common algorithms: ES256, and RS256
        // supportedAlgorithmIDs: [-7, -257],
    });

    // @ts-ignore

    // @ts-ignore
    const userPasskeys = await credentialService.getPassKey(user.id);
    console.log({ userPasskeys });


    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        timeout: 60000,
        // attestationType: 'direct',
        // @ts-ignore
        excludeCredentials: userPasskeys ? userPasskeys.map(passkey => {
            return {
                // id: isoBase64URL.toBuffer(passkey.credential_id),
                // id: base64ToUint8Array(passkey.public_key),
                id: base64ToUint8Array(passkey.credentialID),
                // id: passkey.credential_id,
                type: 'public-key',
                transports: passkey.transports,
            }
        }) : [],
        // authenticatorSelection: {
        //     residentKey: 'preferred',
        //     userVerification: "discouraged",
        //     authenticatorAttachment: "platform"
        // },
        // // Support for the two most common algorithms: ES256, and RS256
        // supportedAlgorithmIDs: [-7, -257],
        attestationType: 'none',
        // excludeCredentials,
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            // requireResidentKey: true,
            residentKey: 'required',
            userVerification: 'preferred',
        },
        supportedAlgorithmIDs: [-7, -257],
    });
    // const options = await generateRegistrationOptions({
    //     rpName,
    //     rpID,
    //     userName: username,
    //     timeout: 60000,
    //     attestationType: 'none',
    //     /**
    //      * Passing in a user's list of already-registered authenticator IDs here prevents users from
    //      * registering the same device multiple times. The authenticator will simply throw an error in
    //      * the browser if it's asked to perform registration when one of these ID's already resides
    //      * on it.
    //      */
    //     // excludeCredentials: devices.map((dev) => ({
    //     //   id: dev.credentialID,
    //     //   type: 'public-key',
    //     //   transports: dev.transports,
    //     // })),
    //     authenticatorSelection: {
    //         residentKey: 'required',
    //         /**
    //          * Wondering why user verification isn't required? See here:
    //          *
    //          * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
    //          */
    //         userVerification: 'preferred',
    //         authenticatorAttachment: 'platform'
    //     },
    //     /**
    //      * Support the two most common algorithms: ES256, and RS256
    //      */
    //     supportedAlgorithmIDs: [-7, -257],
    // });

    // const options = await generateAuthenticationOptions({
    //     timeout: 60000,
    //     allowCredentials: [],
    //     userVerification: 'required',
    //     rpID,
    //     rpName
    // });
    req.session.loggedInUserId = user.id;
    req.session.currentChallenge = options.challenge;
    res.send(options);
    // } catch (error) {
    //     next(error instanceof CustomError ? error : new CustomError('Internal Server Error', 500));
    // }
};

export const handleRegisterFinish = async (req: Request, res: Response, next: NextFunction) => {
    const { body } = req;
    const { username } = body;
    const { currentChallenge, loggedInUserId } = req.session;
    console.log(body);


    if (!loggedInUserId) {
        return next(new CustomError('User ID is missing', 400));
    }

    if (!currentChallenge) {
        return next(new CustomError('Current challenge is missing', 400));
    }

    let user = await userService.getUserByUsername('a');
    console.log(user);

    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge: currentChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
        console.log("DUSTIN");
        console.log({ verification });
        console.log("DUSTIN");
    } catch (err) {
        console.log("DUSTIN_FAILED");

    }

    // @ts-ignore
    const userPasskeys = await credentialService.getPassKey(user.id);
    console.log(userPasskeys);

    // @ts-ignore
    // for (let dbCredential of userPasskeys) {
    //     const options = await generateAuthenticationOptions({
    //         timeout: 60000,
    //         allowCredentials: [],
    //         userVerification: 'required',
    //         rpID,
    //     });
    //     console.log(options);

    //     // const options = await generateAuthenticationOptions({
    //     //     timeout: 60000,
    //     //     allowCredentials: [],
    //     //     userVerification: 'required',
    //     //     rpID,
    //     // });
    //     // const assertionResponse = await SimpleWebAuthnBrowser.startAuthentication(options)

    //     // // @ts-ignore
    //     // dbCredential.credentialID = base64ToUint8Array(dbCredential.credentialID)
    //     // // @ts-ignore
    //     // dbCredential.credentialPublicKey = base64ToUint8Array(dbCredential.credentialPublicKey)
    //     // const opts: VerifyAuthenticationResponseOpts = {
    //     //     response: assertionResponse,
    //     //     expectedChallenge: options.challenge,
    //     //     expectedOrigin: origin,
    //     //     expectedRPID: rpID,
    //     //     authenticator: dbCredential,
    //     // };
    //     // const verification1 = await verifyAuthenticationResponse(opts);
    //     // console.log({ verification1 });
    // }

    // try {
    const verification = await verifyRegistrationResponse({
        response: body as RegistrationResponseJSON,
        expectedChallenge: currentChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        // requireUserVerification: true,
        requireUserVerification: false,
    });

    console.log(verification);
    console.log(verification.verified);
    console.log(verification.registrationInfo);


    if (verification.verified && verification.registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

        const transportsString = JSON.stringify(body.response.transports)

        await credentialService.saveNewCredential(
            loggedInUserId,
            // credentialID,
            // credentialPublicKey,
            uint8ArrayToBase64(credentialID),
            uint8ArrayToBase64(credentialPublicKey),
            counter,
            transportsString);
        res.send({ verified: true });
    } else {
        next(new CustomError('Verification failed', 400));
    }
    // } catch (error) {
    //     next(error instanceof CustomError ? error : new CustomError('Internal Server Error', 500));
    // } finally {
    //     req.session.loggedInUserId = undefined;
    //     req.session.currentChallenge = undefined;
    // }
};