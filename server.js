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
      origin: '*',
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

function checkIfUserExistsInDatabase(db, uniqid) {
   return new Promise(resolve => {
      db.collection('accounts').findOne({ uniqid }, (err, result) => {
         if (err || !result) {
            return resolve(false);
         }
         return resolve(true);
      })
   });
}

async function addFriend(db, userUniqid, friendUniqid) {
   await db.collection('accounts').updateOne({ uniqid: userUniqid }, {
      $pull: { pendingRequests: friendUniqid },
      $addToSet: { friends: friendUniqid }
   })
   await db.collection('accounts').updateOne({ uniqid: friendUniqid }, {
      $addToSet: { friends: userUniqid }
   })
}

async function getUserAndValidateToken(db, token, tokenSelector) {
   const user = await db.collection('accounts').findOne({ "tokenSelector": tokenSelector })
   if (!user) {
      return { success: false, reason: "User not found or tokenSelector is not valid" }
   }
   if (!hash.verify(token, user.token)) {
      return { success: false, reason: 'Invalid token' };
   }
   return { success: true, user: user }
};

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
         res.json({
            success: true,
            token: token,
            selector: tokenSelector,
            uniqid: uniqID,
            nickname: req.body.nickname,
            tag: nicknameTag,
            email: req.body.email
         });
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
      res.json({
         success: true,
         token: token,
         selector: tokenSelector,
         uniqid: user.uniqid,
         nickname: user.nickname,
         tag: user.tag,
         email: req.body.email
      });
   });

   io.on('connection', socket => {
      console.log('socket connected')
      socket._storage = {};
      // give the user 10 seconds to authenticate
      socket._storage.mutex = new Mutex();
      socket._storage.timeout = setTimeout(() => {
         console.log('socket disconnected due to inactivity');
         socket.disconnect(true);
      }, 1000 * 10);

      socket.on('disconnect', () => {
         console.log('socket disconnected');
      });

      socket.on('authenticate', async data => {
         await socket._storage.mutex.runExclusive(async () => {
            if (socket._storage.authenticated) return;
            if (!data?.selector || !data?.token) {
               return socket.emit('auth denied', { reason: 'invalid data' });
            }

            const userResponse = await getUserAndValidateToken(db, data.token, data.selector)
            if (!userResponse.success) {
               return socket.emit('auth denied', userResponse.reason);
            }

            socket._storage.authenticated = true;
            socket._storage.user = userResponse.user;
            clearTimeout(socket._storage.timeout);
            socket.emit('authenticated');
            console.log(`${socket._storage.user.email} authenticated`);

            socket.on('get servers', async () => {
               console.log(`${socket._storage.user.nickname} requested servers`)
               const search = { members: { $in: [socket._storage.user.uniqid] } };
               const servers = await db.collection('servers').find(search).toArray();
               const generalServer = {
                  name: 'General',
                  lastMessage: 'Yooo',
                  id: 'GENERAL_SERVER'
               };
               servers.unshift(generalServer)
               for (const server of servers) {
                  socket.join(server.id);
               }
               socket.emit('servers', servers);
            });

            socket.on('add friend', async data => {
               if (!data?.nickname || !data?.tag) return;
               const friendUniqid = await getUserUniqidByNicknameAndTag(db, data.nickname, data.tag)

               if (!friendUniqid) {
                  //TODO CHANGE LOGIC TO RETURN SUCCESS INSTEAD OF CHECKING NUMBER IF SOMEHOW UNIQID CAN BE 0 
                  return socket.emit('add friend fail', { reason: 'user not found' });
               }
               if (socket._storage.user.uniqid === friendUniqid) {
                  return socket.emit('add friend fail', {
                     reason: 'You can not add yourself to friends'
                  });
               }
               await addUserToFriendRequest(db, socket._storage.user.uniqid, friendUniqid)

               socket.emit('add friend success', { success: true })
            });

            socket.on('accept friend', async data => {
               console.log(`accept friend by ${socket._storage.user.nickname}`)
               console.log(`accept friend id ${data?.uniqid}`)
               if (!data?.uniqid) return;

               if (!await checkIfUserExistsInDatabase(db, data.uniqid)) {
                  console.log('accept friend fail user not found');
                  return socket.emit('add friend fail', { reason: 'user not found' });
               }

               const friendUniqid = data.uniqid;

               if (socket._storage.user.uniqid === friendUniqid) {
                  console.log('accept friend fail cannot add yourself');
                  return socket.emit('accept friend fail', {
                     reason: 'You can not add yourself to friends'
                  });
               }

               const acceptedUser = await db.collection('accounts').findOne({uniqid: friendUniqid});

               if (!acceptedUser) {
                  console.log('accept friend fail user not found')
                  return socket.emit('accept friend fail', {
                     reason: 'User not found'
                  });
               }

               await addFriend(db, socket._storage.user.uniqid, friendUniqid)

               const newServer = {
                  name: `${acceptedUser.nickname} & ${socket._storage.user.nickname}`,
                  creator: socket._storage.user.uniqid,
                  members: [socket._storage.user.uniqid, friendUniqid],
                  id: uuidv4(),
                  dm: true,
                  display: [
                     {id: socket._storage.user.uniqid, name: socket._storage.user.nickname},
                     {id: friendUniqid, name: acceptedUser.nickname}
                  ]
               };
               const { err } = await db.collection('servers').insertOne(newServer);
               if (err) {
                  return console.error(err);
               }
               socket.emit('server created', newServer);

               console.log('accept friend success');
               socket.emit('accept friend success', { success: true })
            });

            socket.on('get friends', async () => {

               //* There should be never a case where pendingReuqest to friends or friends are not found
               //* since they are added when the user is created

               const user = await db.collection('accounts').findOne({uniqid: socket._storage.user.uniqid});

               if (!user) {
                  return socket.emit('get friends fail', { reason: 'critical error' });
               }

               socket._storage.user = user;

               let pendingRequests = await db.collection('accounts').find({ uniqid: { $in: user.pendingRequests } }, { nickname: 1, tag: 1, _id: 0 }).toArray();
               if (!pendingRequests) {
                  return socket.emit('get friends fail', { reason: 'could not get pending requests to friends from database' });
               }

               let friends = await db.collection('accounts').find({ uniqid: { $in: user.friends } }, { nickname: 1, tag: 1, _id: 0 }).toArray();
               if (!friends) {
                  return socket.emit('get friends fail', { reason: 'could not get friends from database' });
               }

               pendingRequests = pendingRequests.map(e => ({ uniqid: e.uniqid, nickname: e.nickname, tag: e.tag }))
               friends = friends.map(e => ({ uniqid: e.uniqid, nickname: e.nickname, tag: e.tag }))
               return socket.emit('get friends success', { success: true, friends, pendingRequests })
            });

            socket.on('get messages', async data => {
               if (!data?.server) return;
               console.log('get messages')
               let server = data.server;
               if (server.length === uniqid().length) {
                  console.log('redirecting get message to server');
                  const search = { members: { $in: [
                     socket._storage.user.uniqid, server
                  ] }, dm: true };
                  const srv = await db.collection('servers').findOne(search)
                  if (!srv) {
                     return console.log('no server found')
                  }
                  server = srv.id;
               }
               const messages = await db.collection('messages').find({server}, {
                  _id: 0,
                  message: 1,
                  server: 1,
                  time: 1,
                  timezone: 1,
                  uuid: 1,
                  userID: 1,
                  user: 1
               })
               .sort({ _id: -1 })
               .limit(50)
               .toArray();
               messages.reverse();
               console.log(`returning ${messages.length} messages`);
               socket.emit('channel messages', { messages, server: data.server });
            });

            socket.on('message', async data => {
               if (!data.message) return;
               let server = data?.server || 'GENERAL_SERVER';
               console.log(`${socket._storage.user.nickname} sent "${data.message}" to ${data?.server}`);

               if (server.length === uniqid().length) {
                  console.log('redirecting message to server');
                  const search = { members: { $in: [
                     socket._storage.user.uniqid, server
                  ] }, dm: true };
                  const srv = await db.collection('servers').findOne(search)
                  if (!srv) {
                     return console.log('no server found')
                  }
                  server = srv.id;
               }

               const newMessage = {
                  message: data.message,
                  server: server,
                  user: socket._storage.user.nickname,
                  time: Date.now(),
                  timezone: serverTimezone,
                  userID: socket._storage.user.uniqid,
                  uuid: uuidv4()
               };
               const { err } = await db.collection('messages').insertOne(newMessage);
               if (err) {
                  return console.error(err);
               }
               io.to(server).emit('message', newMessage);
            });

            socket.on('new server', async data => {
               console.log(`${socket._storage.user.nickname} creates "${data.name}"`);
               const newServer = {
                  name: data.name,
                  creator: socket._storage.user.uniqid,
                  members: [socket._storage.user.uniqid],
                  id: uuidv4()
               };
               const { err } = await db.collection('servers').insertOne(newServer);
               if (err) {
                  return console.error(err);
               }
               socket.emit('server created', newServer);
            })
         });
      });
   });

   const PORT = process.env.PORT || 3000;

   http.listen(PORT, () => {
      console.log('listening on port ' + PORT);
   });

})();