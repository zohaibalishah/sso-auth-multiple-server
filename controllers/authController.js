const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const jwtConfig = require("../config/jwt");
const cca = require("../config/msalConfig");

// In-memory storage for refresh tokens (Replace with DB in production)
const refreshTokens = new Map();

const RefreshToken = {
    save: (data) => {
        refreshTokens.set(data.token, { userId: data.userId, email: data.email });
    },
    find: (token) => {
        const data = refreshTokens.get(token);
        return data ? { token, ...data } : null;
    },
    delete: (token) => {
        refreshTokens.delete(token);
    }
};

const setAuthCookies = (res, accessToken, refreshToken) => {
    const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 15 * 60 * 1000 // 15 mins for access token
    };

    // Support sharing cookies across subdomains if COOKIE_DOMAIN is provided
    if (process.env.COOKIE_DOMAIN) {
        cookieOptions.domain = process.env.COOKIE_DOMAIN;
    }

    res.cookie("access_token", accessToken, cookieOptions);

    if (refreshToken) {
        res.cookie("refresh_token", refreshToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days for refresh token
        });
    }
};

exports.microsoftLogin = async (req, res) => {
    try {
        const authCodeUrlParameters = {
            scopes: ["user.read"],
            redirectUri: `${req.protocol}://${req.get("host")}/auth/callback`
        };
        const response = await cca.getAuthCodeUrl(authCodeUrlParameters);
        res.redirect(response);
    } catch (error) {
        console.error("Microsoft Login Error:", error);
        res.status(500).send("External Authentication initialization failed");
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
            redirectUri: `${req.protocol}://${req.get("host")}/auth/callback`
        });

        const { localAccountId, username } = tokenResponse.account;

        // Access token
        const accessToken = jwt.sign(
            { userId: localAccountId, email: username },
            jwtConfig.accessSecret,
            { expiresIn: jwtConfig.accessExpiry }
        );

        // Refresh token
        const refreshToken = uuidv4();
        RefreshToken.save({ token: refreshToken, userId: localAccountId, email: username });

        setAuthCookies(res, accessToken, refreshToken);
        res.redirect(process.env.FRONTEND_REDIRECT_URL);
    } catch (error) {
        console.error("Microsoft Callback Error:", error);
        res.status(500).send("Authentication failed during callback");
    }
};

exports.refresh = (req, res) => {
    try {
        const token = req.cookies.refresh_token;
        if (!token) return res.status(401).json({ status: 0, message: "No token", loggedIn: false });

        const stored = RefreshToken.find(token);
        if (!stored) return res.status(403).json({ status: 0, message: "Invalid token", loggedIn: false });

        const userId = stored.userId;
        const email = stored.email;

        // Rotate refresh token
        RefreshToken.delete(token);
        const newRefreshToken = uuidv4();
        RefreshToken.save({ token: newRefreshToken, userId: userId, email: email });

        // Generate new access token
        const accessToken = jwt.sign(
            { userId: userId, email: email },
            jwtConfig.accessSecret,
            { expiresIn: jwtConfig.accessExpiry }
        );

        setAuthCookies(res, accessToken, newRefreshToken);
        res.json({ status: 1, message: "Token refreshed", loggedIn: true });
    } catch (error) {
        console.error("Token Refresh Error:", error);
        res.status(500).json({ status: 0, message: "Internal server error during refresh" });
    }
};

exports.logout = (req, res) => {
    const token = req.cookies.refresh_token;
    if (token) {
        RefreshToken.delete(token);
    }

    res.clearCookie("access_token");
    res.clearCookie("refresh_token");
    res.redirect("https://login.microsoftonline.com/common/oauth2/v2.0/logout");
};

exports.me = (req, res) => {
    const token = req.cookies.access_token;
    if (!token) {
        return res.status(401).json({ status: 0, message: "No token", loggedIn: false });
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
        res.status(401).json({ status: 0, message: "Invalid token", loggedIn: false });
    }
};


exports.verify = async (req, res) => {
    const token = req.cookies.access_token;
    if (!token) {
        return res.status(401).json({ status: 0, message: "No token", loggedIn: false });
    }

    try {
        const decoded = jwt.verify(token, jwtConfig.accessSecret);
        res.json({
            status: 1,
            message: "Token verified",
            loggedIn: true,
            user: decoded
        });
    } catch (error) {
        res.status(401).json({ status: 0, message: "Invalid token", loggedIn: false });
    }
};
