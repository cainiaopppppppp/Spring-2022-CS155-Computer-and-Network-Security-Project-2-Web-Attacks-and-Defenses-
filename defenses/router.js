import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import sleep from './utils/sleep';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite')

function render(req, res, next, page, title, errorMsg = false, result = null) {
  res.render(
    'layout/template', {
      page,
      title,
      loggedIn: req.session.loggedIn,
      account: req.session.account,
      errorMsg,
      result,
    }
  );
}

// HMAC的key
const key = generateRandomness();
// 生成HMAC的函数
const generateHMAC = (req) => {
  const currentSessionData = JSON.stringify({loggedIn: req.session.loggedIn})+JSON.stringify({ account: req.session.account});
  return HMAC(key, currentSessionData);
};
// 验证HMAC的函数
const verifyHMAC = (req) => {
  return req.session.HMAC === generateHMAC(req);
};

router.get('/', (req, res, next) => {
  render(req, res, next, 'index', 'Bitbar Home');
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {

  // HMAC验证
  if (!verifyHMAC(req)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  // CSP
  res.setHeader("Content-Security-Policy", "default-src 'self'");

  req.session.account.profile = req.body.new_profile;
  console.log(req.body.new_profile);
  const db = await dbPromise;
  const query = `UPDATE Users SET profile = ? WHERE username = "${req.session.account.username}";`;
  const result = await db.run(query, req.body.new_profile);

  // 生成HMAC
  req.session.HMAC = generateHMAC(req);
  render(req, res, next, 'index', 'Bitbar Home');

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.get('/get_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
  const result = await db.get(query);

  if(result) { // if this username actually exists
    if(checkPassword(req.query.password, result)) { // if password is valid
      await sleep(2000);
      req.session.loggedIn = true;
      req.session.account = result;

      // 生成HMAC
      req.session.HMAC = generateHMAC(req);

      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    } else {
      // 生成一个随机的延迟时间，1800到2300毫秒之间
      var delay = 1800 + Math.random() * 500;
      await sleep(delay);
      render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
      return;
    }
  }
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  let result = await db.get(query);
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  console.log(hashedPassword);
  console.log(salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  req.session.HMAC = generateHMAC(req);
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {

  // HMAC验证
  if (!verifyHMAC(req)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;
  // 参数化查询
  const query = `DELETE FROM Users WHERE username = ?;`;
  await db.get(query, [req.session.account.username]);
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {

  // HMAC验证
  if (!verifyHMAC(req)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    // 参数化查询
    const query = `SELECT * FROM Users WHERE username = ?;`;
    let result;
    try {
      result = await db.get(query, [req.query.username]);
    } catch(err) {
      console.error(err);
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      // 转义特殊字符
      const safeUsername = req.query.username.replace(/&/g, "&amp;")
                                             .replace(/</g, "&lt;")
                                             .replace(/>/g, "&gt;")
                                             .replace(/"/g, "&quot;")
                                             .replace(/'/g, "&#039;");
      render(req, res, next, 'profile/view', 'View Profile', `${safeUsername} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));


router.get('/transfer', (req, res, next) => {

  // HMAC验证
  if (!verifyHMAC(req)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  // 生成CSRF令牌
  req.session.csrf_token = generateRandomness();
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false, {
    receiver:null, amount:null,csrf_token: req.session.csrf_token});
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {

  // HMAC验证
  if (!verifyHMAC(req)) {
    req.session.loggedIn = false;
    req.session.account = {};
  }

  // CSP
  res.setHeader("Content-Security-Policy", "default-src 'self'");

  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  // CSRF令牌验证
  if (!req.body.csrf_token || req.body.csrf_token !== req.session.csrf_token) {
    return res.status(403).send('CSRF token mismatch.');
  }

  delete req.session.csrf_token;

  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null});
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  const receiver = await db.get(query);
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null});
      return;
    }

    req.session.account.bitbars -= amount;
    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    await db.exec(query);
    // 生成HMAC
    req.session.HMAC = generateHMAC(req);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`, {receiver:null, amount:null});
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});

router.get('/steal_password', (req, res, next) => {
  let password = req.query.password;
  let timeElapsed = req.query.timeElapsed;
  console.log(`\n\nPassword: ${req.query.password}, time elapsed: ${req.query.timeElapsed}\n\n`);
  res.end();
});


module.exports = router;
