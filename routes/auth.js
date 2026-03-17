const router = require("express").Router();
const authController = require("../controllers/authController");

router.get("/login/microsoft", authController.microsoftLogin);
router.get("/callback", authController.microsoftCallback);
router.get("/logout/microsoft", authController.logout);
router.get("/me", authController.me);
router.post("/handshake/token", authController.generateSwapToken);
router.post("/handshake/verify", authController.verifySwapToken);


module.exports = router;
