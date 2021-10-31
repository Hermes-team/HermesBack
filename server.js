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

const serverTimezone = moment.tz.guess();

function rand(min, max) {
   return Math.floor(Math.random() * (max - min + 1) + min);
}

function connectToDb() {
   return new Promise(resolve => {
      const uri = `mongodb+srv://ZeusBastard:${process.env.MONGO_PASS}@cluster0.ruyuw.mongodb.net/olympus?retryWrites=true&w=majority`;
      const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
      client.connect(err => {
         if (err) return resolve({ err: err, db: null });
         resolve({ err: null, db: client.db("olympus") });
      });
   });
}

function findUser(db, nickname, tag) {
   //! DODAC OBSLUGE BLEDU JESLI NIE MA UZYTKOWNIKA O DANYM TA 
   return new Promise(resolve => {
      db.collection('accounts').findOne({ nickname: `${nickname}`, tag: tag }, (err, result) => {
         if (err) {
            console.log("User not found");
            return resolve(null);
         }
         return resolve(result._id);
      })
   });
};

function addUser(db, userRequesting, userGettingRequest) {
   return new Promise(resolve => {
      const a = db.collection('accounts').updateOne({ "_id": ObjectId(userGettingRequest) }, {
         $push: { pendingRequests: [`${userRequesting}`] } } 
      )
      if (a && a.n > 0) {
         return resolve(a);
      }
      return resolve({ success: false, reason: 'could not update friends pending request list' });
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
            return resolve({ success: false, err: err, reason: 'db' });
         }
         if (res.length > 8000) {
            return resolve({ success: false, err: err, reason: 'limit reached' });
         }
         while (true) {
            const tag = rand(1, 9999);
            const exists = await db.collection('accounts').findOne({ tag: tag, nickname: nickname });
            if (!exists) {
               return resolve({ success: true, tag: tag });
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
      res.send('index page');
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

      //!CHECK IF USER IS LOGGED

      if (!req.body.token || !req.body.userRequestingTag || !req.body.userRequestingNick || !req.body.userReqestedToAddNickname || !req.body.userReqestedToAddTag) {
         return res.json({
            success: false,
            msg: 'incomplete query'
         });
      }
      const userRequesting = await findUser(db, req.body.userRequestingNick, req.body.userRequestingTag)
      if (!userRequesting) {
         return res.json({
            success: false,
            msg: 'first not found user in database'
         });
      }
      const userGettingRequest = await findUser(db, req.body.userReqestedToAddNickname, req.body.userReqestedToAddTag)
      if (!userGettingRequest) {
         return res.json({
            success: false,
            msg: 'second not found user in database'
         });
      }
      //! Adding to friend

      //* Czy chcemy dodawac do accounts czy osobna tabela ? 

      const user = await addUser(db, userRequesting, userGettingRequest)
      if (!user) {
         return res.json({
            success: false,
            msg: 'Could not add user to pendingRequests'
         });
      }
      return res.send(user);
   });


   io.on('connection', socket => {
      console.log('socket connected')
   });

   const PORT = process.env.PORT || 3000;

   http.listen(PORT, () => {
      console.log('listening on port ' + PORT);
   });

})();