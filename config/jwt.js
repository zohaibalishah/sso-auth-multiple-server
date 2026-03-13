if (!process.env.ACCESS_SECRET || !process.env.REFRESH_SECRET) {
    console.warn("WARNING: JWT Secrets are missing from environment variables. Using unsafe defaults.");
}

module.exports = {
    accessSecret: process.env.ACCESS_SECRET || '1247192739812784912',
    refreshSecret: process.env.REFRESH_SECRET || '1247192739812784912',
    accessExpiry: process.env.ACCESS_EXPIRY || "15m",
    refreshExpiry: process.env.REFRESH_EXPIRY || "7d"
};