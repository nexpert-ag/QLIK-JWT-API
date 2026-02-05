const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const QLIK_CONFIG = {
  issuer: 'xwkva47egjc4kxv.de.qlikcloud.com',   // Qlik Cloud URL
  keyId: '241267e2-73cd-4b0b-83c8-9b2736fd4315', //Public Key
  tenantDomain: 'xwkva47egjc4kxv.de.qlikcloud.com',  // Qlik Cloud Domain
  audience: 'qlik.api/login/jwt-session'
};

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    let privateKey = process.env.QLIK_PRIVATE_KEY;

    if (!privateKey) {
      return res.status(500).json({
        error: 'QLIK_PRIVATE_KEY environment variable not configured',
        message: 'Please add the private key to your Vercel environment variables'
      });
    }

    if (!privateKey.includes('\n') && privateKey.includes('\\n')) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }

    const userId = req.body?.userId || req.query?.userId || 'hubspot-user-' + Date.now();
    const userEmail = req.body?.userEmail || req.query?.userEmail || 'user@hubspot.com';
    const userName = req.body?.userName || req.query?.userName || 'HubSpot User';

    const tokenId = crypto.randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 30 * 60;

    const payload = {
      jti: tokenId,
      sub: userId,
      subType: 'user',
      name: userName,
      email: userEmail,
      email_verified: true,
      aud: QLIK_CONFIG.audience,
      iss: QLIK_CONFIG.issuer,
      iat: now,
      nbf: now,
      exp: now + expiresIn
    };

    const token = jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      keyid: QLIK_CONFIG.keyId,
      header: {
        alg: 'RS256',
        typ: 'JWT',
        kid: QLIK_CONFIG.keyId
      }
    });

    const appId = req.body?.appId || req.query?.appId || '82692ff7-f3ae-4efe-8bb5-7fa603635390';
    const sheetId = req.body?.sheetId || req.query?.sheetId || null;

    let qlikUrl = `https://${QLIK_CONFIG.tenantDomain}/sense/app/${appId}`;

    if (sheetId) {
      qlikUrl += `/sheet/${sheetId}`;
    }

    return res.status(200).json({
      success: true,
      token: token,
      qlikUrl: qlikUrl,
      expiresAt: new Date((now + expiresIn) * 1000).toISOString(),
      user: {
        id: userId,
        email: userEmail,
        name: userName
      },
      qlikConfig: {
        tenantDomain: QLIK_CONFIG.tenantDomain,
        issuer: QLIK_CONFIG.issuer,
        keyId: QLIK_CONFIG.keyId
      }
    });

  } catch (error) {
    return res.status(500).json({
      error: 'Failed to generate JWT token',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};
