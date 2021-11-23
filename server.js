require('dotenv').config()

const { v4: uuidv4 } = require('uuid');
const uniqid = require('uniqid');
const emailValidator = require("email-validator");
const bcrypt = require('bcrypt');
const hash = require('password-hash');
const MongoClient = require('mongodb').MongoClient;
const moment = require('moment-timezone');
const rateLimit = require("express-rate-limit");
const cors = require('cors')
const express = require('express')
const app = express();
const http = require('http').Server(app);
const Mutex = require('async-mutex').Mutex;
const io = require('socket.io')(http, {
   cors: {
      origin: '*/*',
      methods: ['GET', 'POST']
   }
});
const ObjectId = require('mongodb').ObjectID;

function rand(min, max) {
   return Math.floor(Math.random() * (max - min + 1) + min);
}

function connectToDb() {
   return new Promise(resolve => {
      const uri = `mongodb+srv://ZeusBastard:${process.env.MONGO_PASS}@cluster0.ruyuw.mongodb.net/olympus?retryWrites=true&w=majority`;
      const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
      client.connect(err => {
         if (err) return resolve({ err, db: null });
         resolve({ err: null, db: client.db("olympus") });
      });
   });
}

function generateTokens() {
   const token = uuidv4();
   const tokenSelector = uuidv4();
   const hashedToken = hash.generate(token);
   return { token, tokenSelector, hashedToken }
}

function getUserUniqidByNicknameAndTag(db, nickname, tag) {
   return new Promise(resolve => {
      db.collection('accounts').findOne({ nickname, tag }, (err, result) => {
         if (err || !result) {
            console.log("User not found");
            return resolve(null);
         }
         console.log("User found by NicknameAndTag")
         return resolve(result.uniqid);
      })
   });
};

function addFriend(db, userUniqid, friendUniqid) {
   return new Promise(resolve => {
      db.collection('accounts').updateOne({ "uniqid": userUniqid }, {
         $pull: { pendingRequests: friendUniqid }
      })
      db.collection('accounts').updateOne({ "uniqid": userUniqid }, {
         $addToSet: { friends: friendUniqid }
      })
      resolve({ success: true });
   });
}

async function getUserAndValidateToken(db, token, tokenSelector) {
   const user = await db.collection('accounts').findOne({ "tokenSelector": tokenSelector })
   if (!user) {
      return { success: false, reason: "User not found" }
   }
   if (!hash.verify(token, user.token)) {
      return { success: false, reason: 'Invalid token' };
   }
   console.log('Found user')
   return {success: true, user:user}
};

// async function validateUserToken(db, uniqid, token) {
//    const user = await db.collection('accounts').findOne({ uniqid });
//    if (!user) {
//       return { success: false, reason: "User not found" }
//    }
//    if (!hash.verify(token, user.token)) {
//       return { success: false, reason: 'Invalid token' };
//    }
//    console.log('Correcly validated user using token')
//    return { success: true }
// }

async function addUserToFriendRequest(db, userRequestingUniqid, userGettingRequestUniqid) {
   await db.collection('accounts').updateOne({ "uniqid": userGettingRequestUniqid }, {
      $addToSet: { pendingRequests: userRequestingUniqid }
   })
   return { success: true };
};

async function generateUniqueID(db) {
   while (true) {
      const id = uniqid();
      const user = await db.collection('accounts').findOne({ uniqid: id });
      if (!user) {
         return id;
      }
   }
}

async function generateNicknameTag(db, nickname) {
   const res = await db.collection('accounts').find({ nickname }).toArray();
   if (!res) {
      return { success: false, err, reason: 'db' }
   }
   if (res.length > 8000) {
      return { success: false, err, reason: 'limit reached' };
   }
   while (true) {
      const tag = rand(1, 9999);
      const exists = await db.collection('accounts').findOne({ tag, nickname });
      if (!exists) {
         return { success: true, tag };
      }
   }
}


(async () => {
   const { err, db } = await connectToDb();
   if (err) throw err;

   console.log('Connected to the database')

   app.use(cors())

   const limiter = rateLimit({
      windowMs: 60 * 1000 * 1, // 1 minute
      max: 30 // limit 30 requests per window
   });

   app.use(limiter); // apply to all requests

   app.use(express.urlencoded({ extended: true }));
   app.use(express.json());

   const mutex = new Mutex();

   app.get('/', (req, res) => {
      res.end('index page');
   });

   app.post('/register', async (req, res) => {
      if (!req.body.email || !req.body.password || !req.body.nickname) {
         return res.json({
            success: false,
            msg: 'incomplete query'
         });
      }
      req.body.nickname = req.body.nickname.trim()
      if (req.body.nickname.length > 20 || req.body.nickname.length < 1) {
         return res.json({
            success: false,
            msg: 'nickname too long or short'
         });
      }
      if (!emailValidator.validate(req.body.email)) {
         return res.json({
            success: false,
            msg: 'invalid email address'
         });
      }
      if (req.body.password.length > 50 || req.body.password.length < 3) {
         return res.json({
            success: false,
            msg: 'password too long or short'
         });
      }
      await mutex.runExclusive(async () => {
         const tagRes = await generateNicknameTag(db, req.body.nickname);
         if (!tagRes.success) {
            if (tagRes.reason === 'db') {
               return res.json({
                  success: false,
                  msg: 'database error'
               });
            }
            return res.json({
               success: false,
               msg: 'nickname limit reached'
            });
         }
         const emailExists = await db.collection('accounts').findOne({ email: req.body.email });
         if (emailExists) {
            return res.json({
               success: false,
               msg: 'email exists'
            });
         }
         const nicknameTag = tagRes.tag;
         const hashedPassword = await bcrypt.hash(req.body.password, 9);
         const uniqID = await generateUniqueID(db);
         const { token, tokenSelector, hashedToken } = generateTokens()
         const newUser = {
            email: req.body.email,
            password: hashedPassword,
            nickname: req.body.nickname,
            uniqid: uniqID,
            verified: false,
            tag: nicknameTag,
            token: hashedToken,
            tokenTimestamp: Date.now(),
            tokenSelector: tokenSelector,
            pendingRequests: [],
            friends: []
         };
         const { err } = await db.collection('accounts').insertOne(newUser);
         if (err) {
            console.log(err);
            return res.json({ success: false, msg: 'database error' });
         }
         res.json({ success: true, token: token, selector: tokenSelector });
      });
   });

   app.post('/login', async (req, res) => {
      if (!req.body.email || !req.body.password) {
         return res.json({
            success: false,
            msg: 'incomplete query'
         });
      }
      if (!emailValidator.validate(req.body.email)) {
         return res.json({
            success: false,
            msg: 'invalid email address'
         });
      }
      const user = await db.collection('accounts').findOne({ email: req.body.email });
      if (!user) {
         return res.json({
            success: false,
            msg: 'incorrect email or password'
         });
      }
      const passwordMatch = await bcrypt.compare(req.body.password, user.password);
      if (!passwordMatch) {
         return res.json({
            success: false,
            msg: 'incorrect email or password'
         });
      }
      const { token, tokenSelector, hashedToken } = generateTokens()
      await db.collection('accounts').updateOne({ _id: user._id }, {
         $set: {
            token: hashedToken,
            tokenTimestamp: Date.now(),
            tokenSelector: tokenSelector
         }
      })
      res.json({ success: true, token: token, selector: tokenSelector });
   });

   app.post('/addFriend', async (req, res) => {

      if (!req.body.token || !req.body.tokenSelector || !req.body.userReqestedToAddNickname || !req.body.userReqestedToAddTag) {
         return res.json({
            success: false,
            msg: 'incomplete query'
         });
      }
      const userResponse = await getUserAndValidateToken(db, req.body.token, req.body.tokenSelector)
      if (!userResponse.success) {
         return res.json(user);
      }

      const userGettingRequestUniqid = await getUserUniqidByNicknameAndTag(db, req.body.userReqestedToAddNickname, req.body.userReqestedToAddTag)
      if (!userGettingRequestUniqid) {
         return res.json({
            success: false,
            msg: 'second user not found in database'
         });
      }

      if (userResponse.user.uniqid === userGettingRequestUniqid) {
         return res.json({
            success: false,
            msg: 'you can not add yourself to friends'
         });
      }
      const addedUserResponse = await addUserToFriendRequest(db, userResponse.user.uniqid, userGettingRequestUniqid)
      return res.send(addedUserResponse);
   });

   app.post('/acceptFriend', async (req, res) => {
      if (!req.body.token || !req.body.tokenSelector || !req.body.friendNickname || !req.body.friendsTag) {
         return res.json({
            success: false,
            msg: 'incomplete query'
         });
      }
      const userResponse = await getUserAndValidateToken(db, req.body.token, req.body.tokenSelector)
      if (!userResponse.success) {
         return res.json(user);
      }

      const friendUniqid = await getUserUniqidByNicknameAndTag(db, req.body.friendNickname, req.body.friendsTag)
      if (!friendUniqid) {
         return res.json({
            success: false,
            msg: 'Could not find user-friend in database'
         });
      }
      if (userResponse.user.uniqid === friendUniqid) {
         return res.json({
            success: false,
            msg: 'you can not accept yourself as a friend'
         });
      }
      await addFriend(db, userResponse.user.uniqid, friendUniqid)
      return res.send({ success: true });
   })

   app.get('/getFriends', async (req, res) => {
      if (!req.body.token || !req.body.tokenSelector) {
         return res.json({
            success: false,
            msg: 'incomplete query'
         });
      }
      const userResponse = await getUserAndValidateToken(db, req.body.token, req.body.tokenSelector)
      if (!userResponse.success) {
         return res.json(user);
      }

      const user = userResponse.user;

      let pendingRequests = await db.collection('accounts').find({ uniqid: { $in: user.pendingRequests } }, { nickname: 1, tag: 1, _id: 0 }).toArray();
      if (!pendingRequests) {
         return res.json({
            success: false,
            msg: 'could not get pending requests to friends from database'
         });
      }

      let friends = await db.collection('accounts').find({ uniqid: { $in: user.friends } }, { nickname: 1, tag: 1, _id: 0 }).toArray();
      if (!friends) {
         return res.json({
            success: false,
            msg: 'could not get friends from database'
         });
      }

      pendingRequests = pendingRequests.map(e => ({ nickname: e.nickname, tag: e.tag }))
      friends = friends.map(e => ({ nickname: e.nickname, tag: e.tag }))

      return res.json({
         success: true,
         friends: friends,
         pendingRequests: pendingRequests
      });

   });

   io.on('connection', socket => {
      console.log('socket connected')
   });

   const PORT = process.env.PORT || 3000;

   http.listen(PORT, () => {
      console.log('listening on port ' + PORT);
   });

})();