const userModel = require("../models/user.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports.authUser = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  } 
  else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }
  if (!token) {
    return res
      .status(401)
      .json({ message: "Unauthorized." });
  }
  const isBlacklisted = await userModel.findOne({token: token });
  if(isBlacklisted) {
    return res.status(401).json({ message: "Unauthorized" });
  } 

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(decoded._id);
    if (!user) {
      return res
        .status(401)
        .json({ message: "Authentication failed: user not found." });
    }
    req.user = user;
    return next();
  } 
  catch (error) {
    console.error("Authentication error:", error);
    if (error.name === "JsonWebTokenError") {
      return res
        .status(401)
        .json({ message: "Invalid token. Please log in again." });
    } else if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ message: "Token expired. Please log in again." });
    }
    return res
      .status(500)
      .json({ message: "Internal server error.", error: error.message });
  }
};
