require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit")
const app = express();


app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
}))

const PORT = process.env.PORT || 4000;


// CORS for dashboard + apps
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:4000"
    ];

app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));


app.use("/auth", require("./routes/auth"));


app.get("/hello", (req, res) => {
    console.log("cookies", req.cookies)
    return res.send("hello")
})

app.listen(PORT, () => console.log(`Auth Server running on port ${PORT}`));