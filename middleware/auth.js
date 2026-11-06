const { jwtVerify } = require("jose");

const authMiddleware = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "Authorization required" });
  }

  try {
    const secret = new TextEncoder().encode(process.env.JWT_SECRET);
    const { payload } = await jwtVerify(token, secret, {
      algorithms: ["HS256"],
    });
    req.userID = payload.userID;
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }

  next();
};

module.exports = authMiddleware;
