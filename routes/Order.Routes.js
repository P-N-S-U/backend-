const express = require("express");
const Order = require("../models/Order.model");
const Product = require("../models/products.model");
const { protect, consumerOnly, farmerOnly, adminOnly } = require("../middleware/authMiddleware");
const mongoose = require("mongoose");

const PDFDocument = require("pdfkit");

const router = express.Router();

/**  
 *  Place a New Order  
 *  `POST /api/orders`
 *  Only consumers can place orders
 */
router.post("/", protect, consumerOnly, async (req, res) => {
  try {
    const { products } = req.body;

    if (!products || products.length === 0) {
      return res.status(400).json({ message: "No products in the order" });
    }

    let totalPrice = 0;
    let orderItems = [];

    for (let item of products) {
      const product = await Product.findById(item.product);
      if (!product) {
        return res.status(404).json({ message: `Product not found: ${item.product}` });
      }
      totalPrice += product.price * item.quantity;

      // 🔹 Store farmer ID along with the product in the order
      orderItems.push({
        product: product._id,
        farmer: product.farmer, // ✅ Add farmer reference
        quantity: item.quantity
      });
    }

    const order = new Order({
      consumer: req.user.id,
      products: orderItems, // ✅ Now contains farmer ID
      totalPrice
    });

    await order.save();
    res.status(201).json({ message: "Order placed successfully", order });
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});


/**  
 *  Get Orders of a Consumer  
 *  `GET /api/orders/my-orders`
 *  Only the logged-in consumer can see their orders
 */
router.get("/my-orders", protect, consumerOnly, async (req, res) => {
  try {
    const orders = await Order.find({ consumer: req.user.id }).populate("products.product");
    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

/**  
 *  Get Orders for Farmers (Products They Sold)  
 *  `GET /api/orders/farmer-orders`
 *  Only farmers can see orders that contain their products
 */
router.get("/farmer-orders", protect, farmerOnly, async (req, res) => {
  try {
    // Fetch orders that contain products linked to the logged-in farmer
    const orders = await Order.find({ "products.farmer": req.user.id })
      .populate("products.product")
      .populate("consumer", "name email");

    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});


/**  
 *  Update Order Status (Farmer Processing Order)  
 *  `PUT /api/orders/:orderId`
 *  Only farmers can update order status
 */
router.put("/:orderId", protect, farmerOnly, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findById(req.params.orderId).populate({
      path: "products.product",
      populate: { path: "farmer" }
    });

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    // Convert `req.user.id` to ObjectId before comparing
    const loggedInFarmerId = new mongoose.Types.ObjectId(req.user.id);

    // Check if the logged-in farmer owns any product in the order
    const farmerOwnsProduct = order.products.some(p =>
      (p.farmer && p.farmer.equals(loggedInFarmerId)) || 
      (p.product && p.product.farmer && p.product.farmer._id.equals(loggedInFarmerId))
    );

    if (!farmerOwnsProduct) {
      return res.status(403).json({ message: "You cannot update this order" });
    }

    order.status = status;
    await order.save();

    res.json({ message: "Order status updated", order });
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

router.get("/all", protect, adminOnly, async (req, res) => {
  try {
    // Fetch all orders, including consumer details and product details
    const orders = await Order.find()
      .populate("consumer", "name email") // Include consumer details
      .populate({
        path: "products.product",
        populate: { path: "farmer", select: "name email" } // Include farmer details
      });

    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});



router.get("/:orderId/invoice", protect, async (req, res) => {
  try {
    const order = await Order.findById(req.params.orderId).populate("consumer", "name email");

    if (!order) return res.status(404).json({ message: "Order not found" });

    // Create PDF document
    const doc = new PDFDocument();
    res.setHeader("Content-Disposition", `attachment; filename=invoice-${order._id}.pdf`);
    res.setHeader("Content-Type", "application/pdf");

    doc.pipe(res);
    doc.text(`Invoice for Order ID: ${order._id}`);
    doc.text(`Customer: ${order.consumer.name} (${order.consumer.email})`);
    doc.text(`Total Price: $${order.totalPrice}`);
    doc.end();
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});


module.exports = router;
