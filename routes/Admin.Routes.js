const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Admin = require("../models/Admin.model");
const Farmer = require("../models/Farmers.model");
const {protect,adminOnly} = require("../middleware/authMiddleware");

const router = express.Router();

/**  
 *  Admin Login (Only One Admin Exists)  
 *  POST `/api/admins/login`  
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Hardcoded admin email (Only one admin exists)
    const adminEmail = "admin@naturalfarm.com";

    // Check if the email matches the predefined admin
    if (email !== adminEmail) {        
      return res.status(403).json({ message: "Unauthorized access" });
    }
    

    // Fetch admin from DB
    const admin = await Admin.findOne({ email: adminEmail });
    if (!admin) {
      return res.status(404).json({ message: "Admin account not found" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate JWT Token for Admin
    const token = jwt.sign(
      { id: admin._id, email: admin.email, role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Admin login successful", token });
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

router.post("/approve/:id", protect, adminOnly, async (req, res) => {
  try {
    // Ensure only the hardcoded admin can access this route
    if (req.user.email !== "admin@naturalfarm.com") {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const farmer = await Farmer.findById(req.params.id);
    if (!farmer) {
      return res.status(404).json({ message: "Farmer not found" });
    }

    farmer.verified = true;
    await farmer.save();

    res.json({ message: "Farmer approved successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

module.exports = router;
