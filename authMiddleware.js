const jwt = require('jsonwebtoken');
require('dotenv').config();

const verifyToken = (req, res, next) => {
    // 1. Look for the token in the request headers
    const authHeader = req.headers ['authorization'];

    // 2. If no token is found, kick them out
    if (!authHeader) {
        return res.status(403).json({ error: 'Access denied. No token provided.' });
    }
    //Token usually look like "Bearer eyJhbGci..." so we split it to get just the token
    const token = authHeader.split(' ')[1];

    try {
        // 3. Verify the token using the secret key
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // 4. Attatch the user's data (like their role) to the request object for use in other routes
        req.user = decoded;

        // 5. Let them pass
        next();
    } catch {
        // 6. If the token is invalid or expired, kick them out
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

module.exports = verifyToken;