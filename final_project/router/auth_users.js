const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // ✅ Import bcrypt for password hashing
let books = require("./booksdb.js");
const regd_users = express.Router();

let users = [];

require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key'; // ✅ Ensure JWT_SECRET is defined

const isValid = (username) => {
    // ✅ Implement username validation logic
    return users.some(user => user.username === username);
};

// Middleware to authenticate using JWT
function authenticateJWT(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from "Bearer <token>"

    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: "Invalid or expired token" }); // ✅ Improved error message
            }
            req.user = user; // Save user info to request object
            next();
        });
    } else {
        res.status(401).json({ message: "Authorization token is required" }); // ✅ Improved error message
    }
}

const authenticatedUser = (username, password) => {
    const user = users.find(u => u.username === username && u.password === password);
    return user !== undefined;
};

// Login users
regd_users.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log("Login attempt:", username, password);

  if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
  }

  const user = users.find(u => u.username === username);
  if (!user) {
      console.log("User not found");
      return res.status(401).json({ message: "Invalid username or password" });
  }

  console.log("Stored password:", user.password);

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
      console.log("Password does not match");
      return res.status(401).json({ message: "Invalid username or password" });
  }

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

  return res.status(200).json({ message: "Login successful", token });
});

// Add or modify a book review
regd_users.get('/review/:isbn', authenticateJWT, (req, res) => {
    const { review } = req.query; // Get the review from the query parameters
    const isbn = req.params.isbn; // Get the ISBN from the URL parameters
    const username = req.user.username; // Get the username from the decoded token

    // ✅ Use books[isbn] instead of books.find() because books is likely an object
    const book = books[isbn];
    if (!book) {
        return res.status(404).json({ message: "Book not found" });
    }

    // Initialize reviews if undefined
    if (!book.reviews) {
        book.reviews = {};
    }

    // Check if the user has already reviewed this book
    if (book.reviews[username]) {
        book.reviews[username] = review; // Modify existing review
        return res.status(200).json({ message: "Review updated successfully" });
    } else {
        book.reviews[username] = review; // Add new review
        return res.status(201).json({ message: "Review added successfully" });
    }
});

// Delete a book review
regd_users.delete('/auth/review/:isbn', authenticateJWT, (req, res) => {
    const isbn = req.params.isbn;
    const username = req.user.username;

    console.log(`Attempting to delete review for ISBN: ${isbn} by user: ${username}`);

    // ✅ Use books[isbn] instead of books.find()
    const book = books[isbn];
    if (!book) {
        console.log("Book not found");
        return res.status(404).json({ message: "Book not found" });
    }

    // Check if the user has a review for this book
    if (book.reviews && book.reviews[username]) {
        delete book.reviews[username];
        console.log("Review deleted successfully");
        return res.status(200).json({ message: "Review deleted successfully" });
    } else {
        console.log("Review not found for this user");
        return res.status(404).json({ message: "Review not found for this user" });
    }
});

module.exports.authenticated = regd_users;
module.exports.isValid = isValid;
module.exports.users = users;
