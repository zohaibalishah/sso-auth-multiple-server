const router = require("express").Router();
const authController = require("../controllers/authController");

router.get("/login/microsoft", authController.microsoftLogin);
router.get("/callback", authController.microsoftCallback);
router.post("/refresh/microsoft", authController.refresh);
router.get("/logout/microsoft", authController.logout);
router.get("/me", authController.me);
router.get("/verify", authController.verify);

// Cross-app SSO handshake
router.post("/handshake/token", authController.generateTransitionToken);
router.post("/handshake/verify", authController.verifyTransitionToken);


module.exports = router;
