const dotenv = require("dotenv");
dotenv.config();

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
        "http://localhost:4000",
        "https://central-auth-frontend-api-hqcrdef4e2f5fyg9.northeurope-01.azurewebsites.net"
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
app.use((req, res) => {
    res.status(404).send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f172a;
            --text-color: #f8fafc;
            --accent-color: #38bdf8;
            --card-bg: #1e293b;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            overflow: hidden;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 500px;
            animation: fadeIn 0.8s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            font-size: 8rem;
            margin: 0;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
        }
        p {
            font-size: 1.25rem;
            color: #94a3b8;
            margin: 1rem 0 2rem;
        }
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background-color: var(--accent-color);
            color: var(--bg-color);
            text-decoration: none;
            border-radius: 0.5rem;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px -1px rgba(56, 189, 248, 0.2);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(56, 189, 248, 0.3);
            background-color: #7dd3fc;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <p>Oops! The page you're looking for doesn't exist.</p>
        <a href="/" class="btn">Go Back Home</a>
    </div>
</body>
</html>
    `);
});

app.listen(PORT, () => console.log(`Auth Server running on port http://localhost:${PORT}`));
