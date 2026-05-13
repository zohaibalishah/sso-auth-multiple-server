const router = require("express").Router();
const authController = require("../controllers/authController");

router.get("/login/microsoft", authController.microsoftLogin);
router.get("/callback", authController.microsoftCallback);
router.get("/logout/microsoft", authController.logout);
router.get("/me", authController.me);
router.post("/handshake/token", authController.generateSwapToken);
router.post("/handshake/token-v2", authController.generateSwapTokenV2);

router.post("/handshake/verify", authController.verifySwapToken);
router.post("/handshake/callback", authController.verifyHandshakeToken);


module.exports = router;
