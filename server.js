require('dotenv').config()

const { v4: uuidv4 } = require('uuid');
const uniqid = require('uniqid');
const emailValidator = require("email-validator");
const bcrypt = require('bcrypt');
const hash = require('password-hash');
const MongoClient = require('mongodb').MongoClient;
const moment = require('moment-timezone');
const rateLimit = require("express-rate-limit");
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

function getUserUniqidByTokenSelector(db, tokenSelector) {
   return new Promise(resolve => {
      db.collection('accounts').findOne({ tokenSelector }, (err, result) => {
         if (err || !result) {
            return resolve(null);
         }
         console.log('Found user by tokenSelector')
         return resolve(result.uniqid);
      })
   });
};

async function validateUserToken(db, uniqid, token) {
   return new Promise(resolve => {
      db.collection('accounts').findOne({ uniqid }, (err, result) => {
         if (err || !result) {
            return resolve({ success: false, reason: "User not found" });
         }
         if (!hash.verify(token, result.token)) {
            return resolve({ success: false, reason: 'Invalid token' });
         }
         console.log('Correcly validated user using token')
         return resolve({ success: true });
      })
   });
}

function addUserToFriendRequest(db, userRequestingUniqid, userGettingRequestUniqid) {
   return new Promise(resolve => {
      db.collection('accounts').updateOne({ "uniqid": userGettingRequestUniqid }, {
         $addToSet: { pendingRequests: userRequestingUniqid }
      })
      return resolve({ success: true });
   })
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

function generateNicknameTag(db, nickname) {
   return new Promise(resolve => {
      db.collection('accounts').find({ nickname: `${nickname}` }).toArray(async (err, res) => {
         if (err) {
            return resolve({ success: false, err, reason: 'db' });
         }
         if (res.length > 8000) {
            return resolve({ success: false, err, reason: 'limit reached' });
         }
         while (true) {
            const tag = rand(1, 9999);
            const exists = await db.collection('accounts').findOne({ tag, nickname });
            if (!exists) {
               return resolve({ success: true, tag });
            }
         }
      });
   });
}

(async () => {
   const { err, db } = await connectToDb();
   if (err) throw err;

   console.log('Connected to the database')

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
         const newUser = {
            email: req.body.email,
            password: hashedPassword,
            nickname: req.body.nickname,
            uniqid: uniqID,
            verified: false,
            tag: nicknameTag,
            tokenSelector: null,
            token: null,
            tokenTimestamp: null
         };
         const { err } = await db.collection('accounts').insertOne(newUser);
         if (err) {
            console.log(err);
            return res.json({ success: false, msg: 'database error' });
         }
         res.json({ success: true });
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
      const token = uuidv4();
      const tokenSelector = uuidv4();
      const hashedToken = hash.generate(token);
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
      const userRequesting = await getUserUniqidByTokenSelector(db, req.body.tokenSelector)
      if (!userRequesting) {
         return res.json({
            success: false,
            msg: 'first user not found in database'
         });
      }
      const tokenValidation = await validateUserToken(db, userRequesting, req.body.token)
      if (!tokenValidation.success) {
         return res.json(tokenValidation);
      }
      const userGettingRequest = await getUserUniqidByNicknameAndTag(db, req.body.userReqestedToAddNickname, req.body.userReqestedToAddTag)
      if (!userGettingRequest) {
         return res.json({
            success: false,
            msg: 'second user not found in database'
         });
      }
      if (userGettingRequest === userRequesting) {
         return res.json({
            success: false,
            msg: 'you can not yourself to friends'
         });
      }
      const addedUserResponse = await addUserToFriendRequest(db, userRequesting, userGettingRequest)
      return res.send(addedUserResponse);
   });


   io.on('connection', socket => {
      console.log('socket connected')
   });

   const PORT = process.env.PORT || 3000;

   http.listen(PORT, () => {
      console.log('listening on port ' + PORT);
   });

})();