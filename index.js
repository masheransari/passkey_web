const express = require('express');
const path = require('path'); 
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const SimpleWebAuthnServer = require('@simplewebauthn/server');
const base64url = require('base64url');

app.use(cors({ origin: '*' }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

let users = {};
let challenges = {};
const rpId = 'com.karwatechnologies.customcred';
const expectedOrigin = ['http://localhost:3300', 'https://allinone.boomerce.com', 'android:apk-key-hash:P4TgIy8vetaoWOq_IWrCFc7W4nroZirr2aa1YY62TN4'];

app.listen(process.env.PORT || 3300, err => {
    if (err) throw err;
    console.log('Server started on port', process.env.PORT || 3300);
});
app.use(express.static(path.join(__dirname, 'passkey-frontend/dist/passkey-frontend/browser')));

var serveIndex = require('serve-index');
app.use('/.well-known', express.static('.well-known'), serveIndex('.well-known'));

app.post('/register/start', (req, res) => {
    let username = req.body.username;
    console.log("Register Request: ", username);

    let challenge = getNewChallenge();
    challenges[username] = convertChallenge(challenge);
    const pubKey = {
        challenge: challenges[username],
        rp: {id: rpId, name: 'Custom Cred'},
        user: {id: username, name: username, displayName: username},
        pubKeyCredParams: [
            {type: 'public-key', alg: -7},
            {type: 'public-key', alg: -257},
        ],
        authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
            requireResidentKey: false,
        }
    };

    console.log("Register Request Response: ", pubKey);

    res.json(pubKey);
});

app.post('/register/finish', async (req, res) => {
    const username = req.body.username;

    console.log("Register Validation: username=", username);
    console.log("Register Validation: data=", req.body.data);
    console.log("Register Validation: challenge=", challenges[username]);

    // Verify the attestation response
    let verification;
    let responseData = JSON.parse(req.body.data);
    const { id, rawId } = responseData;

    console.log("Register Validation: id=", id);
    console.log("Register Validation: rawId=", rawId);

    try {
        verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
            response: responseData,
            expectedChallenge: challenges[username],
            expectedOrigin: expectedOrigin
        });
    } catch (error) {
        console.error(error);
        return res.status(400).send({error: error.message});
    }
    const {verified, registrationInfo} = verification;

    console.log("Register Validation Status: ", verified);

    if (verified) {
        users[username] = registrationInfo;
        return res.status(200).send({
            "status": true
        });
    }

    res.status(500).send({
        "status": false
    });
});

app.post('/login/start', (req, res) => {
    let username = req.body.username;
    console.log("Login Start: username=", username);
    
    if (!users[username]) {
        return res.status(404).send(false);
    }
    
    let challenge = getNewChallenge();
    challenge = convertChallenge(challenge);
    challenges[username] = challenge;
    
    console.log("Login Start: challenge=", challenge);

    res.json({
        challenge,
        rpId,
        allowCredentials: [{
            type: 'public-key',
            id: users[username].credentialID,
            transports: ['internal'],
        }],
        userVerification: 'preferred',
    });
});

app.post('/login/finish', async (req, res) => {
    let username = req.body.username;
    console.log("Login Finish: username=", username);
    if (!users[username]) {
       return res.status(404).send(false);
    }

    console.log("Login Finish: challenge=", challenges[username]);
    console.log("Login Finish: response=", req.body.data);
    let responseData = JSON.parse(req.body.data);

    let verification;
    try {
        const user = users[username];
        verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
            expectedChallenge: challenges[username],
            response: responseData,
            authenticator: user,
            expectedRPID: rpId,
            expectedOrigin,
            requireUserVerification: false
        });
    } catch (error) {
        console.error(error);
        return res.status(400).send({error: error.message});
    }
    const {verified} = verification;
    return res.status(200).send({
        res: verified
    });
});

function getNewChallenge() {
    return Math.random().toString(36).substring(2);
}

function convertChallenge(challenge) {
    return btoa(challenge).replaceAll('=', '');
}
