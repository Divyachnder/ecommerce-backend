const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// ================= In-memory "Database" =================
let users = [];      // { username, passwordHash, role }
let products = [];   // { id, name, price, seller }

// JWT Secret (for simplicity, hard-coded)
const JWT_SECRET = "supersecretkey";

// ================= Middleware =================
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token provided" });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { username, role }
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
}

// ================= Auth Routes =================
app.post('/api/auth/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash, role });
  res.json({ message: "User registered successfully" });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: "Invalid username or password" });
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) return res.status(400).json({ message: "Invalid username or password" });
  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// ================= Products Routes =================
app.get('/api/products', (req, res) => {
  res.json(products);
});

app.post('/api/products', authenticate, (req, res) => {
  if (req.user.role !== "seller") {
    return res.status(403).json({ message: "Access denied: Only sellers can perform this action" });
  }
  const { name, price } = req.body;
  if (!name || price == null) return res.status(400).json({ message: "Name and price required" });
  const newProduct = { id: products.length + 1, name, price, seller: req.user.username };
  products.push(newProduct);
  res.status(201).json(newProduct);
});

app.put('/api/products/:id', authenticate, (req, res) => {
  if (req.user.role !== "seller") {
    return res.status(403).json({ message: "Access denied: Only sellers can perform this action" });
  }
  const product = products.find(p => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ message: "Product not found" });
  const { name, price } = req.body;
  if (name) product.name = name;
  if (price != null) product.price = price;
  res.json(product);
});

app.delete('/api/products/:id', authenticate, (req, res) => {
  if (req.user.role !== "seller") {
    return res.status(403).json({ message: "Access denied: Only sellers can perform this action" });
  }
  products = products.filter(p => p.id !== parseInt(req.params.id));
  res.json({ message: "Product deleted" });
});

// ================= Start Server =================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
