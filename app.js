const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(bodyParser.json());
const secretKey = 'supersecretkey';

mongoose.connect('mongodb+srv://architchanana:XvEdPadeFXkV9ZFf@banking-app.299es03.mongodb.net/banking-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('Error connecting to MongoDB:', error);
});


const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);


const accountSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bankAccountNumber: { type: String, required: true },
  sortCode: { type: String, required: true },
  status: { type: String, default: 'ACTIVE' },
  allowCredit: { type: Boolean, default: true },
  allowDebit: { type: Boolean, default: true },
  dailyWithdrawalLimit: { type: Number, default: 1000.0 },
  balance: { type: Number, default: 0.0 }
});
const Account = mongoose.model('Account', accountSchema);

// Transaction Schema and Model
const transactionSchema = new mongoose.Schema({
  accountId: { type: mongoose.Schema.Types.ObjectId, ref: 'Account', required: true },
  amount: { type: Number, required: true },
  type: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = await User.create({ username, password: hashedPassword });
    res.status(201).send({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).send({ message: 'Error registering user', error });
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers['x-access-token'];
  if (!token) return res.status(403).send({ message: 'No token provided' });

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Failed to authenticate token' });
    req.userId = decoded.id;
    next();
  });
};

const verifyTokenUser = (jwt_i)=>{
  let userId=0;
  try {
    const decoded = jwt.verify(jwt_i, secretKey);
    console.log('Decoded JWT:', decoded);
  
    // Access the id value within the try block
    userId = decoded.id;
    console.log('User ID:', userId);
  } catch (e) {
    console.error('Error verifying JWT:', e.message);
  }

  return userId;
}

app.post('/account', verifyToken, async (req, res) => {
  try {
    const { bankAccountNumber, sortCode, status } = req.body;
    length_of_account = bankAccountNumber.length
    if(length_of_account>10){
      return res.status(401).send({message:" Account Number should be less than 10 digits"})
    }
    const account_checking = await Account.findOne({ bankAccountNumber: bankAccountNumber });
    console.log(account_checking)
    if (account_checking){
      return res.status(401).send({message:"An account with similar name is found, please use someother accountnumber"})
    }
    const account = await Account.create({
      userId: req.userId,
      bankAccountNumber,
      sortCode,
      status
    });
   

    res.status(201).send({ message: 'Account created successfully', account });
  } catch (error) {
    res.status(400).send({ message: 'Error creating account', error });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username: username });
    console.log(user);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: 86400 });
    res.status(200).send({ message: 'Login successful', token });
  } catch (error) {
    res.status(400).send({ message: 'Error logging in', error });
  }
});

app.post('/transaction', verifyToken, async (req, res) => {
  try {
    const { accountId, amount, type } = req.body;
    const account = await Account.findOne({ bankAccountNumber: accountId });
    if (!account) return res.status(404).send({ message: 'Account not found' });

    if (account.status !== 'ACTIVE') {
      return res.status(400).send({ message: 'Account is not active' });
    }

    if (type === 'DEBIT' && !account.allowDebit) {
      return res.status(400).send({ message: 'Debit transactions are not allowed on this account' });
    }
    if (type === 'CREDIT' && !account.allowCredit) {
      return res.status(400).send({ message: 'Credit transactions are not allowed on this account' });
    }
    if (type == 'DEBIT'){
      const id = verifyTokenUser(req.headers['x-access-token'])
      const checking = await Account.findOne({ bankAccountNumber: accountId });
      const userId = checking.userId.toString();
      if (id!=userId){
        return res.status(403).json({
          message:"You are not authorized"
        })
      }
    }
    if (type === 'DEBIT') {
      const today = new Date().setHours(0, 0, 0, 0);
      const transactions = await Transaction.find({
        accountId: account._id, // Use _id instead of id for MongoDB
        type: 'DEBIT',
        timestamp: { $gte: today }
      });
      
      if (account.balance === 0 || account.balance < amount) {
        return res.status(400).send({ message: 'Insufficient balance for debit transaction' });
      }
      
      const totalDailyWithdrawals = transactions.reduce((sum, tx) => sum + tx.amount, 0);
      if (totalDailyWithdrawals + amount > account.dailyWithdrawalLimit) {
        return res.status(400).send({ message: 'Daily withdrawal limit exceeded' });
      }
      account.balance -= amount;
    } else if (type === 'CREDIT') {
      account.balance += amount;
    }

    await account.save();
    const transaction = new Transaction({
      accountId: account._id, // Use _id instead of id for MongoDB
      amount,
      type
    });
    await transaction.save();
    res.status(201).send({ message: 'Transaction successful', transaction });
  } catch (error) {
    res.status(400).send({ message: 'Error processing transaction', error });
  }
});

app.get('/balance/:accountId', verifyToken, async (req, res) => {
  try {
    const account = await Account.findOne({ bankAccountNumber: req.params.accountId });
    if (!account) return res.status(404).send({ message: 'Account not found' });
    res.status(200).send({ balance: account.balance });
  } catch (error) {
    res.status(400).send({ message: 'Error fetching balance', error });
  }
});

app.post('/get_accounts', async(req,res)=>{
  try{
    const { username, password } = req.body;
    const user = await User.findOne({ username: username });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ message: 'Invalid credentials' });
    }
    id_user = user._id
    account = await Account.find({userId: id_user})
    const bankAccountNumbers = [];
    for (let i = 0; i < account.length; i++) {
      bankAccountNumbers.push(account[i].bankAccountNumber);
    }
    return res.status(200).json({"accounts":bankAccountNumbers})
  }
  catch(e){
    res.status(500).send({message:"Not able to fetch accounts"})
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
