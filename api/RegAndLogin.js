require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    minlength: 8,
    maxlength: 27,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/^\S+@\S+\.\S+$/, 'Invalid email format'],
  },
  employeeRole: {
    type: String,
    required: true,
  },
  telephone: {
    type: String,
    required: true,
    match: [/^01\d{9}$/, 'Invalid phone number'],
  },
  nationalId: {
    type: String,
    required: true,
    match: [/^\d{14}$/, 'Invalid national ID'],
  },
  password: {
    type: String,
    required: true,
  },
  address: {
    type: String,
    required: true,
  },
});

// Set the collection name to 'RegAndLogin' explicitly
const User = mongoose.model('User', userSchema, 'RegAndLogin');

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expecting 'Bearer <token>'

  if (!token)
    return res
      .status(401)
      .json({ message: 'Access denied, no token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user; // Attach the decoded token payload to the request object
    next(); // Proceed to the next middleware/route handler
  });
};

// POST route to register a new user
app.post('/register', async (req, res) => {
  const {
    name,
    email,
    employeeRole,
    telephone,
    nationalId,
    password,
    rePassword,
    address,
  } = req.body;

  // Password validation
  if (!password || password !== rePassword) {
    return res
      .status(400)
      .json({ message: "Passwords don't match or are missing" });
  }

  try {
    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user
    const newUser = new User({
      name,
      email,
      employeeRole,
      telephone,
      nationalId,
      password: hashedPassword,
      address,
    });

    // Save the user to the database
    await newUser.save();

    // Create a JWT token including 'name'
    const token = jwt.sign(
      {
        userId: newUser._id,
        email: newUser.email,
        role: newUser.employeeRole,
        name: newUser.name,
      }, // Added 'name' here
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send the token to the client
    res
      .status(201)
      .json({ message: 'User registered successfully', token: token });
  } catch (error) {
    res
      .status(500)
      .json({ message: 'Error registering user', error: error.message });
  }
});

// POST route for user login (with email or telephone)
app.post('/login', async (req, res) => {
  const { email, telephone, password } = req.body;

  try {
    // Find the user by either email or telephone
    const user = await User.findOne({
      $or: [{ email: email }, { telephone: telephone }],
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: 'Invalid email, telephone, or password' });
    }

    // Check if the password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: 'Invalid email, telephone, or password' });
    }

    // Create a JWT token including 'name'
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        role: user.employeeRole,
        name: user.name,
      }, // Added 'name' here
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send the token to the client
    res.status(200).json({ message: 'Login successful', token: token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Protected route example (only accessible with a valid token)
app.get('/protected-route', authenticateToken, (req, res) => {
  res.json({ message: 'Access to protected route granted', user: req.user });
});

// Root route for health check
app.get('/', (req, res) => {
  res.send('Registration and Login API with JWT is running');
});

// Start the server
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

module.exports = app;
