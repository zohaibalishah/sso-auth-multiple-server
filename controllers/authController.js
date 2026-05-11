const jwt = require("jsonwebtoken");
const jwtConfig = require("../config/jwt");
const cca = require("../config/msalConfig");


const setAuthCookies = (res, accessToken) => {

    // Check if we are running on localhost/development
    const cookieOptions = {
        httpOnly: true,
        secure: true, // Required for SameSite=None
        sameSite: 'none', // Required for cross-origin cookies
        maxAge: 30 * 60 * 1000 // 30 minutes
    };

    // Support sharing cookies across subdomains if COOKIE_DOMAIN is provided
    if (process.env.COOKIE_DOMAIN) {
        cookieOptions.domain = process.env.COOKIE_DOMAIN;
    }

    res.cookie("access_token", accessToken, cookieOptions);

};

exports.microsoftLogin = async (req, res) => {
    try {
        const authCodeUrlParameters = {
            scopes: ["user.read"],
            redirectUri: process.env.CALLBACK_REDIRECT_URL
        };
        const response = await cca.getAuthCodeUrl(authCodeUrlParameters);
        res.redirect(response);
    } catch (error) {
        console.error("Microsoft Login Error:", error);
        res.status(500).send({ status: 0, message: "External Authentication initialization failed" });
    }
};

exports.microsoftCallback = async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) {
            return res.status(400).send("Missing code");
        }

        const tokenResponse = await cca.acquireTokenByCode({
            code,
            scopes: ["user.read"],
            redirectUri: process.env.CALLBACK_REDIRECT_URL
        });
        const { localAccountId, username } = tokenResponse.account;

        // Access token
        const accessToken = jwt.sign(
            { userId: localAccountId, email: username },
            jwtConfig.accessSecret,
            { expiresIn: '30m' }
        );


        setAuthCookies(res, accessToken);

        const msIdTokenOptions = {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 30 * 60 * 1000 // 30 minutes
        };
        if (process.env.COOKIE_DOMAIN) {
            msIdTokenOptions.domain = process.env.COOKIE_DOMAIN;
        }
        res.cookie("ms_id_token", tokenResponse.idToken, msIdTokenOptions);

        // Generate a short-lived transition token for the URL
        const transitionToken = jwt.sign(
            { userId: localAccountId, email: username, type: 'transition' },
            jwtConfig.accessSecret,
            { expiresIn: '1m' }
        );

        // Redirect to frontend with token in query params
        const frontendUrl = process.env.FRONTEND_REDIRECT_URL;
        const url = new URL(frontendUrl);
        url.searchParams.append("token", transitionToken);

        res.redirect(url.toString());
    } catch (error) {
        console.error("Microsoft Callback Error:", error);
        res.status(500).send({ status: 0, message: error.message });
    }
};



exports.logout = (req, res) => {
    const msIdToken = req.cookies.ms_id_token;
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/'
    };
    // Support sharing cookies across subdomains if COOKIE_DOMAIN is provided
    // const cookieOptions = {};
    if (process.env.COOKIE_DOMAIN) {
        cookieOptions.domain = process.env.COOKIE_DOMAIN;
    }

    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("ms_id_token", cookieOptions);

    const frontendUrl = encodeURIComponent(process.env.FRONTEND_REDIRECT_URL)
    const postLogoutRedirectUri = frontendUrl + "/login";

    const tenantId = process.env.MS_TENANT_ID || "common";
    const clientId = process.env.MS_CLIENT_ID;

    // Create Microsoft logout URL with required parameters
    const logoutEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri=${postLogoutRedirectUri}`;
    // const logoutUrl = new URL(logoutEndpoint);

    // post_logout_redirect_uri is only honored if id_token_hint or client_id is provided
    // logoutUrl.searchParams.append("post_logout_redirect_uri", postLogoutRedirectUri);

    // if (clientId) {
    //     logoutUrl.searchParams.append("client_id", clientId);
    // }

    // if (msIdToken) {
    //     logoutUrl.searchParams.append("id_token_hint", msIdToken);
    // }
    console.log(logoutEndpoint);

    return res.redirect(logoutEndpoint);
};

exports.me = (req, res) => {
    // Check cookie first, then fallback to Authorization header
    let token = req.cookies.access_token;

    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1]; // Extract from "Bearer <token>"
    }

    if (!token) {
        return res.status(401).json({ status: 0, message: "Session timeout", loggedIn: false });
    }

    try {
        const user = jwt.verify(token, jwtConfig.accessSecret);
        res.json({
            status: 1,
            message: "Token verified",
            loggedIn: true,
            user
        });
    } catch (error) {
        res.status(401).json({ status: 0, message: error.message, loggedIn: false });
    }
};




exports.generateSwapToken = async (req, res) => {
    // Check cookie first, then fallback to Authorization header
    let token = req.cookies.access_token;

    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ status: 0, message: "No token found" });
    }

    try {
        const user = jwt.verify(token, jwtConfig.accessSecret);
        const transitionToken = jwt.sign(
            {
                userId: user.userId,
                email: user.email,
                type: 'transition',
            },
            jwtConfig.accessSecret,
            {
                expiresIn: '1m',
            }
        );

        res.json({ status: 1, token: transitionToken });
    } catch (error) {
        res.status(401).json({ status: 0, message: error.message });
    }
};
const tokenUsed = new Set();

exports.verifySwapToken = async (req, res) => {
    const { token, targetApp } = req.body;
    if (!token) {
        return res.status(400).json({ status: 0, message: "Token required" });
    }

    try {
        const decoded = jwt.verify(token, jwtConfig.accessSecret);
        if (decoded.type !== 'transition') {
            return res.status(400).json({ status: 0, message: "Invalid token type" });
        }

        if (tokenUsed.has(token)) {
            return res.status(403).json({ status: 0, message: "Token has already been used" });
        }

        tokenUsed.add(token);

        setTimeout(() => {
            tokenUsed.delete(token);
        }, 120000);

        res.json({
            status: 1,
            user: { userId: decoded.userId, email: decoded.email }
        });
    } catch (error) {
        res.status(401).json({ status: 0, message: "Token expired, invalid, or wrong audience" });
    }
};

// Dedicated for internal frontend login to bypass cookie issues
exports.verifyHandshakeToken = async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ status: 0, message: "Token required" });
    }

    try {
        const decoded = jwt.verify(token, jwtConfig.accessSecret);
        if (decoded.type !== 'transition') {
            return res.status(400).json({ status: 0, message: "Invalid token type" });
        }

        if (tokenUsed.has(token)) {
            return res.status(403).json({ status: 0, message: "Token has already been used" });
        }

        tokenUsed.add(token);

        setTimeout(() => {
            tokenUsed.delete(token);
        }, 120000);

        // Generate a fresh long-lived access token for the frontend to store
        const accessToken = jwt.sign(
            { userId: decoded.userId, email: decoded.email },
            jwtConfig.accessSecret,
            { expiresIn: '30m' }
        );

        res.json({
            status: 1,
            user: { userId: decoded.userId, email: decoded.email },
            token: accessToken
        });
    } catch (error) {
        res.status(401).json({ status: 0, message: "Token expired or invalid" });
    }
};
