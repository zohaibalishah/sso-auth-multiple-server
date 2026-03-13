const router = require("express").Router();
const authController = require("../controllers/authController");

router.get("/login/microsoft", authController.microsoftLogin);
//callback need to fix
router.get("/", authController.microsoftCallback);
router.post("/refresh/microsoft", authController.refresh);
router.get("/logout/microsoft", authController.logout);

router.get("/me", authController.me);
router.get("/silent-login", authController.silentLogin);

// all apis call this
router.get("/verify", authController.verify);


module.exports = router;
