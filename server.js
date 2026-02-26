const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = 3000;
const SECRET = "demo_cashapp_secret";

const users = [];

app.post('/register', async (req,res)=>{
  const {username,email,password} = req.body;
  if(users.find(u=>u.email===email)) return res.json({success:false,message:"Email already exists"});
  const passwordHash = await bcrypt.hash(password,8);
  users.push({username,email,passwordHash,balance:0,transactions:[]});
  res.json({success:true,message:"Registration successful"});
});

app.post('/login', async (req,res)=>{
  const {email,password} = req.body;
  const user = users.find(u=>u.email===email);
  if(!user) return res.json({success:false,message:"User not found"});
  const match = await bcrypt.compare(password,user.passwordHash);
  if(!match) return res.json({success:false,message:"Wrong password"});
  const token = jwt.sign({email},SECRET,{expiresIn:'2h'});
  res.json({success:true,message:"Login successful",token});
});

function auth(req,res,next){
  const token = req.headers['authorization']?.split(' ')[1];
  if(!token) return res.json({success:false,message:"Unauthorized"});
  try { req.user = jwt.verify(token,SECRET); next(); } 
  catch(e){ return res.json({success:false,message:"Invalid token"}); }
}

app.get('/dashboard', auth, (req,res)=>{
  const user = users.find(u=>u.email===req.user.email);
  if(!user) return res.json({success:false,message:"User not found"});
  res.json({success:true,username:user.username,balance:user.balance,transactions:user.transactions});
});

app.post('/add', auth, (req,res)=>{
  const {amount} = req.body;
  if(amount<=0) return res.json({success:false,message:"Invalid amount"});
  const user = users.find(u=>u.email===req.user.email);
  user.balance += amount;
  user.transactions.push({type:'receive',from:'Bank',to:user.email,amount,date:new Date()});
  res.json({success:true,message:"Funds added"});
});

app.post('/send', auth, (req,res)=>{
  const {toEmail,amount} = req.body;
  if(amount<=0) return res.json({success:false,message:"Invalid amount"});
  const sender = users.find(u=>u.email===req.user.email);
  const recipient = users.find(u=>u.email===toEmail);
  if(!recipient) return res.json({success:false,message:"Recipient not found"});
  if(sender.balance<amount) return res.json({success:false,message:"Insufficient balance"});
  sender.balance -= amount;
  recipient.balance += amount;
  const now = new Date();
  sender.transactions.push({type:'send',from:sender.email,to:recipient.email,amount,date:now});
  recipient.transactions.push({type:'receive',from:sender.email,to:recipient.email,amount,date:now});
  res.json({success:true,message:"Money sent"});
});

app.listen(PORT,()=>console.log(`Demo server running at http://localhost:${PORT}`));
