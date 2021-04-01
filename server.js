const express = require('express')
const mongodb = require('mongodb')
const cors = require('cors')
const dotenv = require('dotenv')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const salt = 10;
const router = express()
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const Mail = require('nodemailer/lib/mailer');
router.use(cookieParser())
router.use(express.json())
router.use(cors())
dotenv.config()


const mongoClient = mongodb.MongoClient;
const DB_URL   = process.env.DB_URL || "mongodb://127.0.0.1:27017";
const port = process.env.PORT||5000;
const EMAIL = process.env.EMAIL;
const PASSWORD = process.env.PASSWORD;
let env = "https://quirky-kirch-1ce3bc.netlify.app/"
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: EMAIL,
        pass: PASSWORD,
    }
})

const hashGenerator = async (plainPassword) => {

    const salted = await bcrypt.genSalt(salt);
    const hash = await bcrypt.hash(plainPassword,salted)
    return hash;

}

const hashValidator = async(plainPassword,hashedPassword) => {
    const result  = await bcrypt.compare(plainPassword,hashedPassword);
    return result;
}

const tokenGenerator = (email) => {

    const token = jwt.sign(
        {email},
        process.env.JWT_Security,
        {expiresIn:"1hours"})
        return token;
}

function authVerify(req,res,next){
  if(req.headers.authorization !=undefined){
      console.log(req.headers.authorization);
    jwt.verify(req.headers.authorization,process.env.JWT_Security,(err,decode) => {
      if(decode){
        next();
      }else{
        res.status(500).json({message:"not authirizs"})
      }
    })
  }
}


router.post('/register',async (req,res)=> {
    try{
        const hashPassword = await hashGenerator(req.body.password)
        const client = await mongoClient.connect(DB_URL,{ useNewUrlParser: true, useUnifiedTopology: true })
        const db = client.db('Login_register')
        const data = {
           name:req.body.name,
           email:req.body.email,
           password:hashPassword
        }
     const record = await db.collection('login').findOne({ email: req.body.email });
    if(record){
        res.json({message:"User email already exists"})
    }else{
      await db.collection('login').insertOne(data);
      client.close()
      res.status(200).json({message:"Registered"})     
    }}
    catch(error){
        console.log(error)
        res.sendStatus(500);
    }
})

router.post("/login",async(req,res)=> {
    try{
        const client = await mongoClient.connect(DB_URL,{ useNewUrlParser: true, useUnifiedTopology: true })
        const db = client.db('Login_register')
        const record = await db.collection('login').findOne({ email: req.body.email });
        if(!record){
          res.status(404).json({message:"User not found"})
        }else {
            const checkUser= await hashValidator(req.body.password,record.password);
            if(!checkUser){
              res.status(500).json({message:"Username or password is incorrect"})
        }else {
            const token = await tokenGenerator(record.email)
            res.status(200).json({message:"Login Successful",token})
        }
        }
        client.close()
    }catch(error){
            console.log(error)
    }
})

router.post('/forgot', async function (req, res, next) {
    const client = await mongoClient.connect(DB_URL,{ useNewUrlParser: true, useUnifiedTopology: true })
    client.connect(async (err) => {
      const db = await client.db("Login_register");
      const result = await db.collection("login").findOne({ email: req.body.email });
      if (!!result) {
        let r = Math.random().toString(36).substring(7);
        await db.collection("login").updateOne({ email: req.body.email }, { $set: { random_string: r } });
        const baseURL = req.protocol + '://' + req.get('host');
  
        let info = await transporter.sendMail({
          from: '"Reset Password Request" <no-reply@checkmailvj.com>', // sender address
          to: req.body.email, // list of receivers
          subject: `Forgot Password - ${req.body.email}`, // Subject line
          text: 'Click the below link to set your password', // plain text body
          html: `${baseURL}/reset/${req.body.email}/${r}`, // html body
        });
  
        console.log('Message sent: %s', info.messageId);
        res.json({ message: 'An email has been sent to you. Please check your mail box', statusCode: 200 });
      } else {
        res.json({ message: "User Doesn't exist!!", statusCode: 500 });
      }
  
      client.close();
    });
  });

  router.get('/reset/:email/:id', async function (req, res, next) {
    const client = await mongoClient.connect(DB_URL,{ useNewUrlParser: true, useUnifiedTopology: true })
  
    client.connect(async (err) => {
      const db = await client.db("Login_register");
      const result = await db.collection("login").findOne({ random_string: req.params.id });
      if (!!result) {
        res.redirect(`${env}reset-password/${req.params.email}`);
      } else {
        res.json({ message: 'The link is invalid. Please try again!', statusCode: 500 });
      }
      client.close();
    });
  });

  router.put('/reset', async function (req, res, next) {
    const client = await mongoClient.connect(DB_URL,{ useNewUrlParser: true, useUnifiedTopology: true })
  
    client.connect(async (err) => {
      const db = await client.db("Login_register");
      const result = await db.collection("login").updateOne({ email: req.body.email }, { $set: { password: req.body.password } });
      if (!!result) {
      //  await db.collection("login").updateOne({ email: req.body.email }, { $unset: { random_string: 1 } });
        res.json({ message: 'New password is set successfully', statusCode: 200 });
      } else {
        res.json({ message: 'The link is invalid , else you may used it earlier!', statusCode: 500 });
      }
      client.close();
    });
});

router.get("/protected",authVerify,(req,res)=>{
  res.status(200).json({message:"I am from Protected route"})
})

router.get("/",(req,res)=>{
  res.send("Express server")
})
router.listen(port,()=>{
    console.log(`Server is running on ${port}`)
})

