const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const verifyToken = require("./authMiddleware");
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const PDFDocument = require('pdfkit');
const { ZipArchive } = require('archiver');
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const multer = require('multer');
const path = require('path');
const fs = require('fs');

// 1. Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// 2. Configure Multer Storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        // Creates a unique filename like: item-1692837465.jpg
        cb(null, 'item-' + Date.now() + path.extname(file.originalname)); 
    }
});
const upload = multer({ storage: storage });

// 3. Serve the uploads folder publicly so the app can load the images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
})

db.getConnection((err, connection)=>{
    if (err) {
        console.error("❌ Database connection failed:", err);
    } else {
        console.log("✅ Database connected successfully");
        connection.release();
    }
});

app.get("/", (req, res) => {
    res.send("Hello from the backend!");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// ==========================================
// 🛠️ TEMPORARY ROUTE: Create First Admin
// ==========================================

app.post('/setup-admin', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        const query = 'INSERT INTO APP_USERS (username, password_hash, role) VALUES (?, ?, ?)';
        db.query(query, ['superadmin', hashedPassword, 'ADMIN'], (err, result) => {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            res.json({ message: "Admin created! Username: superadmin, Password: admin123" });
        });
    } catch (error) {
        res.status(500).json({ error: "Server error during setup." });
    }
});

// ==========================================
// 🔐 THE REAL ROUTE: Login System
// ==========================================

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM APP_USERS WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) 
            return res.status(500).json({ error: err.message });
        // if no user found, return 401 Unauthorized
        if (results.length === 0) {
            return res.status(401).json({ error: "Invalid username or password" });
        }
        // if admin suspended, return 403 Forbidden
        const user = results[0];
        if (user.account_status === 'SUSPENDED') {
            return res.status(403).json({ error: "Your account has been suspended" });
        }
        
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid username or password" });
        }

        const token = jwt.sign(
            { userId: user.user_id, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '12h' }
        );

        res.status(200).json({ 
            message: "Login successful!",
            token: token,   
            role: user.role
        });
    });
});

// ==========================================
// 📦 INVENTORY ROUTE (Protected)
// ==========================================
// Any logged-in user (Admin or Sales) can view items
app.get('/items', verifyToken, (req, res) => {
    const isArchived = req.query.archived === 'true';
    const query = isArchived
        ? `SELECT item_id, barcode, item_name, item_group_id, gst_percentage, mrp, purchase_rate, sale_rate, stock, unit, image_url 
           FROM ITEM WHERE is_active = FALSE`
        : `SELECT item_id, barcode, item_name, item_group_id, gst_percentage, mrp, purchase_rate, sale_rate, stock, unit, image_url 
           FROM ITEM WHERE is_active = TRUE`;
    db.query(query, (err, results) => {
        if (err) 
            if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.put('/items/:id/restore', verifyToken, async (req, res) => {
    const itemId = req.params.id;

    try {
        const restoreQuery = 'UPDATE item SET is_active = TRUE WHERE item_id = ?';
        const [result] = await db.promise().query(restoreQuery, [itemId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No item found with that ID!" });
        }
        res.status(200).json({ message: "Item restored successfully!" });
    } catch (error) {
        console.error("Database Restore Error:", error);
        res.status(500).json({ error: "Failed to restore item" });
    }
});

// ==========================================
// 🧑‍🤝‍🧑 CUSTOMER ROUTE (Protected)
// ==========================================
// Registering a new customer
app.post('/customer', verifyToken, async (req, res) => {
    const customer_name = req.body.customer_name || '';
    const country_code = req.body.country_code || req.body.code || ''; 
    const phone_number = req.body.phone_number || '';
    const alternate_number = req.body.alternate_number || '';
    const email = req.body.email || '';
    const current_address = req.body.current_address || '';
    const permanent_address = req.body.permanent_address || '';
    const city = req.body.city || '';
    const state = req.body.state || '';
    const pincode = req.body.pincode || '';

    try {
        const query = 'INSERT INTO CUSTOMER (customer_name, country_code, phone_number, alternate_number, email, current_address, permanent_address, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
        const values = [customer_name, country_code, phone_number, alternate_number, email, current_address, permanent_address, city, state, pincode];
        const [result] = await db.promise().query(query, values);

        res.status(201).json({ 
            message: "Customer added successfully!", 
            insertId: result.insertId 
        });
    }catch (error) {
        console.error("Database Insert Error:", error);
        res.status(500).json({ error: "Failed to add customer to database" });
    }
});

app.get('/customers', verifyToken, async (req, res) => {
    try {
        const query = 'SELECT * FROM CUSTOMER ORDER BY customer_name ASC';
        const [rows] = await db.promise().query(query);
        res.status(200).json(rows);
    } catch (error) {
        console.error("Fetch Customers Error:", error);
        res.status(500).json({ error: "Failed to fetch customers from database" });
    }
});

app.put('/customer/:id', async (req, res) => {
    const customerId = req.params.id;
    const customer_name = req.body.customer_name || '';
    const country_code = req.body.country_code || req.body.code || ''; 
    const phone_number = req.body.phone_number || '';
    const alternate_number = req.body.alternate_number || '';
    const email = req.body.email || '';
    const current_address = req.body.current_address || '';
    const permanent_address = req.body.permanent_address || '';
    const city = req.body.city || '';
    const state = req.body.state || '';
    const pincode = req.body.pincode || '';

    try {
        const updateQuery = `
            UPDATE customer 
            SET customer_name = ?, country_code = ?, phone_number = ?, 
                alternate_number = ?, email = ?, current_address = ?, 
                permanent_address = ?, city = ?, state = ?, pincode = ?
            WHERE customer_id = ?
        `;
        
        const values = [
            customer_name, country_code, phone_number, alternate_number, 
            email, current_address, permanent_address, city, state, pincode, 
            customerId
        ];
        const [result] = await db.promise().query(updateQuery, values);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No customer found with that ID!" });
        }
        res.status(200).json({ message: "Customer updated successfully!" });
    } catch (error) {
        console.error("Database Update Error:", error);
        res.status(500).json({ error: "Failed to update customer in database" });
    }
});

// 🧾 UTILITY: Calculate Indian FY for Invoices (e.g., returns "2627")
const getInvoiceFY = () => {
    const date = new Date();
    const month = date.getMonth(); // 0 = Jan, 11 = Dec
    const year = date.getFullYear();

    let startYear, endYear;
    // Indian FY starts in April (Month Index 3)
    if (month >= 3) {
        startYear = year.toString().slice(-2);
        endYear = (year + 1).toString().slice(-2);
    } else {
        startYear = (year - 1).toString().slice(-2);
        endYear = year.toString().slice(-2);
    }
    
    return `${startYear}${endYear}`; 
};

// ==========================================
// 🛒 CHECKOUT ROUTE (Transactions)
// ==========================================
app.post('/checkout', verifyToken, (req, res) => {
    const { 
        customer_id, 
        items, 
        total_tax_amount, 
        grand_total, 
        payment_method 
    } = req.body;

    db.getConnection((err, connection) => {
        if (err) return res.status(500).json({ error: "Database connection failed" });

        connection.beginTransaction((err) => {
            if (err) {
                connection.release();
                return res.status(500).json({ error: "Failed to start transaction" });
            }

            // 🚀 NEW LOGIC: Generate Smart Invoice Number securely inside the transaction
            const fy = getInvoiceFY();
            const prefix = `INV-${fy}-`;
            const lastInvoiceQuery = `SELECT invoice_number FROM SALES WHERE invoice_number LIKE ? ORDER BY invoice_number DESC LIMIT 1`;

            connection.query(lastInvoiceQuery, [`${prefix}%`], (err, existingInvoices) => {
                if (err) {
                    return connection.rollback(() => {
                        connection.release();
                        res.status(500).json({ error: "Failed to fetch invoice sequence." });
                    });
                }

                let newSequence = 1;
                if (existingInvoices.length > 0) {
                    const lastInvoice = existingInvoices[0].invoice_number;
                    const lastSequence = parseInt(lastInvoice.split('-')[2], 10);
                    newSequence = lastSequence + 1;
                }

                const paddedSequence = newSequence.toString().padStart(4, '0');
                const generatedInvoiceNumber = `${prefix}${paddedSequence}`;

                // STEP A: Insert into the SALES table (The Header)
                const salesQuery = `
                    INSERT INTO SALES (invoice_number, customer_id, total_tax_amount, grand_total, payment_method) 
                    VALUES (?, ?, ?, ?, ?)
                `;
                
                connection.query(salesQuery, [generatedInvoiceNumber, customer_id, total_tax_amount, grand_total, payment_method], (err, salesResult) => {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            res.status(500).json({ error: "Failed to create sales record." });
                        });
                    }

                    const newSaleId = salesResult.insertId;

                    // STEP B: Insert into the SALES_ITEM table (The Line Items)
                    const salesItemsData = items.map(item => [
                        newSaleId, 
                        item.item_id, 
                        item.sale_rate, 
                        item.quantity, 
                        item.tax_amount, 
                        item.amount
                    ]);

                    const itemsQuery = `
                        INSERT INTO SALES_ITEM (sale_id, item_id, sale_rate, quantity, tax_amount, amount) 
                        VALUES ?
                    `;

                    connection.query(itemsQuery, [salesItemsData], (err, itemsResult) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                res.status(500).json({ error: "Failed to insert line items." });
                            });
                        }
                        
                        // We use a recursive function to safely loop through the items array using callbacks
                        const deductInventoryStock = (index) => {
                            
                            if (index === items.length) {
                                connection.commit((err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            res.status(500).json({ error: "Failed to commit transaction." });
                                        });
                                    }
                                    connection.release();
                                    
                                    // 🚀 Ensure the new generated number is sent back to the frontend
                                    return res.status(201).json({ 
                                        message: "Checkout successful and inventory updated!", 
                                        invoice_number: generatedInvoiceNumber,
                                        sale_id: newSaleId
                                    });
                                });
                                return;
                            }

                            const currentItem = items[index];
                            const stockUpdateQuery = `UPDATE ITEM SET stock = stock - ? WHERE item_id = ?`;

                            connection.query(stockUpdateQuery, [currentItem.quantity, currentItem.item_id], (err, result) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        res.status(500).json({ error: `Failed to update stock for item ID ${currentItem.item_id}.` });
                                    });
                                }
                                
                                deductInventoryStock(index + 1);
                            });
                        };
                        
                        deductInventoryStock(0);
                    });
                });
            });
        });
    });
});

app.delete('/customers/:id', async (req, res) => {
    const customerId = req.params.id;

    try {
        const deleteQuery = 'DELETE FROM customer WHERE customer_id = ?';
        const [result] = await db.promise().query(deleteQuery, [customerId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No customer found with that ID!" });
        }

        res.status(200).json({ message: "Customer deleted successfully!" });
    } catch (error) {
        console.error("Database Delete Error:", error);
        res.status(500).json({ error: "Failed to delete customer from database" });
    }
});

app.post('/items', async (req, res) => {
    const barcode = req.body.barcode || '';
    const item_name = req.body.item_name || '';
    const item_group_id = req.body.item_group_id || '';
    const gst_percentage = parseFloat(req.body.gst_percentage) || 0;
    const mrp = parseFloat(req.body.mrp) || 0;
    const purchase_rate = parseFloat(req.body.purchase_rate) || 0;
    const sale_rate = parseFloat(req.body.sale_rate) || 0;
    const stock = parseInt(req.body.stock) || 0;
    const unit = req.body.unit || '';
    const image_url = req.body.image_url || null;

    try {
        const insertQuery = `
            INSERT INTO item 
            (barcode, item_name, item_group_id, gst_percentage, mrp, purchase_rate, sale_rate, stock, unit, image_url) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [
            barcode, item_name, item_group_id, gst_percentage, 
            mrp, purchase_rate, sale_rate, stock, unit, image_url
        ];
        const [result] = await db.promise().query(insertQuery, values);

        res.status(201).json({ 
            message: "Item added successfully!", 
            insertId: result.insertId 
        });
        
    } catch (error) {
        console.error("Database Insert Item Error:", error);
        res.status(500).json({ error: "Failed to add item to database" });
    }
});

// ==========================================
// 📸 IMAGE UPLOAD ROUTE
// ==========================================
app.post('/upload-image', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "No image provided" });
    }
    
    // Construct the full URL to send back to the frontend
    const imageUrl = `/uploads/${req.file.filename}`;
    res.status(200).json({ image_url: imageUrl });
});

app.delete('/items/:id', verifyToken, async (req, res) => {
    const itemId = req.params.id;

    try {
        const archiveQuery = 'UPDATE item SET is_active = FALSE WHERE item_id = ?';
        const [result] = await db.promise().query(archiveQuery, [itemId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No item found with that ID!" });
        }
        res.status(200).json({ message: "Item archived successfully!" });
    } catch (error) {
        console.error("Database Delete Error:", error);
        res.status(500).json({ error: "Failed to archive item" });
    }
});

app.put('/items/:id', async (req, res) => {
    const itemId = req.params.id;
    
    const barcode = req.body.barcode || '';
    const item_name = req.body.item_name || '';
    const item_group_id = req.body.item_group_id || '';
    const gst_percentage = parseFloat(req.body.gst_percentage) || 0;
    const mrp = parseFloat(req.body.mrp) || 0;
    const purchase_rate = parseFloat(req.body.purchase_rate) || 0;
    const sale_rate = parseFloat(req.body.sale_rate) || 0;
    const stock = parseInt(req.body.stock) || 0;
    const unit = req.body.unit || '';

    try {
        const updateQuery = `
            UPDATE item 
            SET barcode = ?, item_name = ?, item_group_id = ?, 
                gst_percentage = ?, mrp = ?, purchase_rate = ?, 
                sale_rate = ?, stock = ?, unit = ?
            WHERE item_id = ?
        `;
        
        const values = [
            barcode, item_name, item_group_id, gst_percentage, 
            mrp, purchase_rate, sale_rate, stock, unit, itemId
        ];

        const [result] = await db.promise().query(updateQuery, values);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No item found with that ID!" });
        }

        res.status(200).json({ message: "Item updated successfully!" });
    } catch (error) {
        console.error("Database Update Item Error:", error);
        res.status(500).json({ error: "Failed to update item in database" });
    }
});

app.get('/groups', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT item_group_id, group_name 
            FROM item_group 
            ORDER BY group_name ASC
        `;
        const [results] = await db.promise().query(query);

        res.status(200).json(results);
        
    } catch (error) {
        console.error("Error fetching item groups:", error);
        res.status(500).json({ error: "Failed to fetch item groups from database." });
    }
});

// ==========================================
// 🧾 INVOICE & RESTOCKING ROUTES 
// ==========================================

// 1. Fetch all Invoices for the main screen
app.get('/invoices', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT s.sale_id, s.invoice_number, s.grand_total, s.payment_method, s.sale_date, 
                   c.customer_name, c.phone_number, c.current_address
            FROM SALES s
            LEFT JOIN CUSTOMER c ON s.customer_id = c.customer_id
            ORDER BY s.sale_date DESC
        `;
        const [invoices] = await db.promise().query(query);
        res.status(200).json(invoices);
    } catch (error) {
        console.error("Fetch Invoices Error:", error);
        res.status(500).json({ error: "Failed to fetch invoices" });
    }
});

app.delete('/invoices/:id', verifyToken, async (req, res) => {
    const saleId = req.params.id;
    const connection = await db.promise().getConnection();

    try {
        await connection.beginTransaction();
        const getItemsQuery = 'SELECT item_id, quantity FROM SALES_ITEM WHERE sale_id = ?';
        const [soldItems] = await connection.query(getItemsQuery, [saleId]);
        for (let item of soldItems) {
            const restockQuery = 'UPDATE ITEM SET stock = stock + ? WHERE item_id = ?';
            await connection.query(restockQuery, [item.quantity, item.item_id]);
        }
        await connection.query('DELETE FROM SALES_ITEM WHERE sale_id = ?', [saleId]);
        const [deleteResult] = await connection.query('DELETE FROM SALES WHERE sale_id = ?', [saleId]);
        if (deleteResult.affectedRows === 0) {
            throw new Error("Invoice not found.");
        }
        await connection.commit();
        res.status(200).json({ message: "Invoice deleted and stock revised successfully!" });

    } catch (error) {
        await connection.rollback();
        console.error("Delete Invoice Error:", error);
        res.status(500).json({ error: "Failed to delete invoice and revise stock." });
    } finally {
        connection.release();
    }
});

app.get('/invoices/:id/items', verifyToken, async (req, res) => {
    const saleId = req.params.id;
    try {
        const query = `
            SELECT si.item_id, si.quantity, si.sale_rate, si.tax_amount, si.amount, i.item_name, i.barcode 
            FROM SALES_ITEM si
            LEFT JOIN ITEM i ON si.item_id = i.item_id
            WHERE si.sale_id = ?
        `;
        const [items] = await db.promise().query(query, [saleId]);
        res.status(200).json(items);
    } catch (error) {
        console.error("Fetch Invoice Items Error:", error);
        res.status(500).json({ error: "Failed to fetch invoice details" });
    }
});

app.post('/item-groups', verifyToken, async (req, res) => {
    const { group_name } = req.body;
    
    if (!group_name) {
        return res.status(400).json({ error: "Group name is required." });
    }

    try {
        const query = 'INSERT INTO item_group (group_name) VALUES (?)';
        const [result] = await db.promise().query(query, [group_name]);
        res.status(201).json({ 
            item_group_id: result.insertId, 
            group_name: group_name 
        });
    } catch (error) {
        console.error("Create Group Error:", error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: "This group already exists!" });
        }
        res.status(500).json({ error: "Failed to create item group." });
    }
});

// ==========================================
// 📊 Top Selling Item Route (Transactions)
// ==========================================
app.get('/reports/monthly-top-items', verifyToken, async (req, res) => {
    try {
        // This query fetches the total quantity sold for every item, grouped by month
        const query = `
            SELECT 
                DATE_FORMAT(s.sale_date, '%b') AS month_name,
                MONTH(s.sale_date) AS month_num,
                i.item_name,
                SUM(si.quantity) AS total_sold
            FROM SALES_ITEM si
            JOIN SALES s ON si.sale_id = s.sale_id
            JOIN ITEM i ON si.item_id = i.item_id
            GROUP BY month_num, month_name, i.item_name
            ORDER BY month_num ASC, total_sold DESC
        `;
        
        const [results] = await db.promise().query(query);
        const topItemsPerMonth = [];
        const seenMonths = new Set();

        for (const row of results) {
            if (!seenMonths.has(row.month_num)) {
                topItemsPerMonth.push({
                    month: row.month_name,
                    itemName: row.item_name,
                    totalSold: Number(row.total_sold)
                });
                seenMonths.add(row.month_num);
            }
        }

        res.status(200).json(topItemsPerMonth);
    } catch (error) {
        console.error("Report Fetch Error:", error);
        res.status(500).json({ error: "Failed to fetch report data" });
    }
});

// ==========================================
// 🏭 MANUFACTURING & RAW MATERIALS
// ==========================================
app.post('/raw-materials', verifyToken, async (req, res) => {
    const { barcode, item_name, category, purchase_rate, stock, unit } = req.body;
    if (!item_name) return res.status(400).json({ error: "Item name is required" });

    try {
        const query = 'INSERT INTO raw_materials (barcode, item_name, category, purchase_rate, stock, unit) VALUES (?, ?, ?, ?, ?, ?)';
        const [result] = await db.promise().query(query, [barcode || null, item_name, category || null, purchase_rate || 0, stock || 0, unit || '']);
        res.status(201).json({ raw_id: result.insertId, message: "Raw material added successfully!" });
    } catch (error) {
        console.error("Raw Material Error:", error);
        res.status(500).json({ error: "Failed to add raw material" });
    }
});

app.get('/raw-materials', verifyToken, async (req, res) => {
    try {
        const [results] = await db.promise().query('SELECT * FROM raw_materials ORDER BY item_name ASC');
        res.status(200).json(results);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch raw materials" });
    }
});

// ==========================================
// 🏭 1. RAW MATERIAL LEDGER (WITH UNIT)
// ==========================================
app.get('/raw-material-logs', verifyToken, async (req, res) => {
    try {
        // 🚀 FIXED: Join with raw_materials to grab the 'unit' column
        const query = `
            SELECT l.*, r.item_name, r.unit 
            FROM raw_material_monthly_log l
            JOIN raw_materials r ON l.raw_id = r.raw_id
            ORDER BY l.financial_year DESC, l.month_name DESC
        `;
        const [results] = await db.promise().query(query);
        res.status(200).json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 🏭 RAW MATERIALS: UPDATE & DELETE
// ==========================================

// 3. Update Raw Material (Name, Rate, or Stock)
app.put('/raw-materials/:id', verifyToken, async (req, res) => {
    const { barcode, item_name, category, purchase_rate, stock, unit } = req.body;
    try {
        await db.promise().query(
            'UPDATE raw_materials SET barcode = ?, item_name = ?, category = ?, purchase_rate = ?, stock = ?, unit = ? WHERE raw_id = ?',
            [barcode || null, item_name, category || null, purchase_rate || 0, stock || 0, unit || ' ', req.params.id]
        );
        res.status(200).json({ message: "Raw material updated successfully!" });
    } catch (error) {
        console.error("Update Raw Material Error:", error);
        res.status(500).json({ error: "Failed to update raw material" });
    }
});

// 4. Delete Raw Material
app.delete('/raw-materials/:id', verifyToken, async (req, res) => {
    try {
        await db.promise().query('DELETE FROM raw_materials WHERE raw_id = ?', [req.params.id]);
        res.status(200).json({ message: "Raw material deleted successfully!" });
    } catch (error) {
        console.error("Delete Raw Material Error:", error);
        res.status(500).json({ error: "Failed to delete raw material" });
    }
});

// ==========================================
// 🏭 SAVE PRODUCTION & UPDATE FY LEDGER (MULTI-ITEM)
// ==========================================
app.post('/production', verifyToken, async (req, res) => {
    const barcode = req.body.barcode || '';
    const item_name = req.body.item_name || '';
    const item_group_id = req.body.item_group_id ? parseInt(req.body.item_group_id) : null;
    const gst_percentage = parseFloat(req.body.gst_percentage) || 0;
    const mrp = parseFloat(req.body.mrp) || 0;
    const purchase_rate = parseFloat(req.body.purchase_rate) || 0;
    const sale_rate = parseFloat(req.body.sale_rate) || 0;
    const units_produced = parseInt(req.body.units_produced) || 1;
    const unit = req.body.unit || '';
    const used_materials = req.body.used_materials || [];

    try {
        await db.promise().query('START TRANSACTION');

        const insertItemQuery = `
            INSERT INTO item (barcode, item_name, item_group_id, gst_percentage, mrp, purchase_rate, sale_rate, stock, unit) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE 
                stock = stock + VALUES(stock),
                mrp = VALUES(mrp),
                purchase_rate = VALUES(purchase_rate),
                sale_rate = VALUES(sale_rate)
        `;
        await db.promise().query(insertItemQuery, [
            barcode, item_name, item_group_id, gst_percentage, 
            mrp, purchase_rate, sale_rate, units_produced, unit
        ]);

        await db.promise().query(
            'INSERT INTO production_logs (item_name, units_produced, unit) VALUES (?, ?, ?)',
            [item_name, units_produced, unit]
        );

        // 🚀 NEW: Save this recipe for future use
        await db.promise().query('DELETE FROM item_recipe WHERE barcode = ?', [barcode]);
        for (const mat of used_materials) {
            await db.promise().query(
                'INSERT INTO item_recipe (barcode, raw_id, qty, unit) VALUES (?, ?, ?, ?)', 
                [barcode, mat.id, mat.qty, mat.unit]
            );
        }

        const date = new Date();
        const month_name = date.toLocaleString('default', { month: 'long' });
        const year = date.getFullYear();
        const financial_year = date.getMonth() >= 3 ? `${year}-${year + 1}` : `${year - 1}-${year}`;

        for (const material of used_materials) {
            const [rawCheck] = await db.promise().query('SELECT stock, unit FROM raw_materials WHERE raw_id = ?', [material.id]);
            if (rawCheck.length === 0) throw new Error(`Raw material ${material.name} not found.`);
            
            const currentRawStock = parseFloat(rawCheck[0].stock);
            const dbUnit = (rawCheck[0].unit || '').toLowerCase();
            const recipeUnit = (material.unit || '').toLowerCase();
            let deductionQty = parseFloat(material.qty);

            if (dbUnit === 'kg' && recipeUnit === 'g') deductionQty = deductionQty / 1000;
            else if (dbUnit === 'g' && recipeUnit === 'kg') deductionQty = deductionQty * 1000;
            else if (dbUnit === 'l' && recipeUnit === 'ml') deductionQty = deductionQty / 1000;
            else if (dbUnit === 'ml' && recipeUnit === 'l') deductionQty = deductionQty * 1000;
            else if (dbUnit === 'm' && recipeUnit === 'cm') deductionQty = deductionQty / 100;
            else if (dbUnit === 'cm' && recipeUnit === 'm') deductionQty = deductionQty * 100;

            if (currentRawStock < deductionQty) {
                throw new Error(`Not enough ${material.name}! You need ${deductionQty} ${rawCheck[0].unit || 'units'}, but only have ${currentRawStock} left.`);
            }

            await db.promise().query('UPDATE raw_materials SET stock = stock - ? WHERE raw_id = ?', [deductionQty, material.id]);

            const ledgerQuery = `
                INSERT INTO raw_material_monthly_log (raw_id, financial_year, month_name, stock_start, stock_used) 
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE stock_used = stock_used + ?
            `;
            await db.promise().query(ledgerQuery, [
                material.id, financial_year, month_name, currentRawStock, deductionQty, deductionQty
            ]);
        }

        await db.promise().query('COMMIT');
        res.status(201).json({ message: "Production recorded and ledgers updated!" });

    } catch (error) {
        await db.promise().query('ROLLBACK');
        console.error("Production Error:", error);
        res.status(400).json({ error: error.message || "Failed to process production." });
    }
});

// ==========================================
// 🏭 3. GET PRODUCTION HISTORY
// ==========================================
app.get('/production-logs', verifyToken, async (req, res) => {
    try {
        const [results] = await db.promise().query('SELECT * FROM production_logs ORDER BY production_date DESC');
        res.status(200).json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 🏭 4. FETCH EXISTING RECIPE BY BARCODE
// ==========================================
app.get('/production/recipe/:barcode', verifyToken, async (req, res) => {
    try {
        const [items] = await db.promise().query('SELECT * FROM item WHERE barcode = ? LIMIT 1', [req.params.barcode]);
        if (items.length === 0) return res.status(404).json({ message: "Item not found" });
        
        const [recipe] = await db.promise().query(`
            SELECT ir.raw_id as id, rm.item_name as name, ir.qty, ir.unit 
            FROM item_recipe ir 
            JOIN raw_materials rm ON ir.raw_id = rm.raw_id 
            WHERE ir.barcode = ?
        `, [req.params.barcode]);

        res.status(200).json({ item: items[0], recipe });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 🧾 RETURN / PARTIALLY REFUND AN INVOICE ITEM
// ==========================================
app.post('/invoices/:sale_id/return-item', verifyToken, async (req, res) => {
    const sale_id = req.params.sale_id;
    const { item_id, return_quantity } = req.body;

    try {
        await db.promise().query('START TRANSACTION');

        const [saleItems] = await db.promise().query(
            'SELECT * FROM SALES_ITEM WHERE sale_id = ? AND item_id = ?', 
            [sale_id, item_id]
        );

        if (saleItems.length === 0) {
            throw new Error("Item not found in this invoice.");
        }

        const saleItem = saleItems[0];
        const returnQty = parseInt(return_quantity);

        if (returnQty > saleItem.quantity || returnQty <= 0) {
            throw new Error("Invalid return quantity.");
        }

        const deductionAmount = saleItem.sale_rate * returnQty;
        const deductionTax = (saleItem.tax_amount / saleItem.quantity) * returnQty; 

        if (returnQty === saleItem.quantity) {
            await db.promise().query('DELETE FROM SALES_ITEM WHERE sale_id = ? AND item_id = ?', [sale_id, item_id]);
        } else {
            await db.promise().query(
                'UPDATE SALES_ITEM SET quantity = quantity - ?, amount = amount - ?, tax_amount = tax_amount - ? WHERE sale_id = ? AND item_id = ?',
                [returnQty, deductionAmount, deductionTax, sale_id, item_id]
            );
        }

        await db.promise().query(
            'UPDATE SALES SET grand_total = grand_total - ?, total_tax_amount = total_tax_amount - ? WHERE sale_id = ?',
            [deductionAmount, deductionTax, sale_id] 
        );

        // 🚀 RESTOCK INVENTORY
        const [updateResult] = await db.promise().query(
            'UPDATE item SET stock = stock + ? WHERE item_id = ?', 
            [returnQty, item_id]
        );

        if (updateResult.affectedRows === 0) {
             throw new Error(`Failed to update stock. Item ID ${item_id} might not exist in the item table.`);
        }

        await db.promise().query('COMMIT');
        res.status(200).json({ message: "Item returned successfully and inventory restocked!" });
    } catch (error) {
        await db.promise().query('ROLLBACK');
        console.error("Return Item Error:", error);
        res.status(400).json({ error: error.message || "Failed to process return." });
    }
});

// ==========================================
// 🧾 2. DELETE ENTIRE INVOICE & RESTOCK ALL
// ==========================================
app.delete('/invoices/:sale_id', verifyToken, async (req, res) => {
    const sale_id = req.params.sale_id;
    
    try {
        await db.promise().query('START TRANSACTION');

        // 🚀 1. THE FIX: Fetch ALL items from this invoice BEFORE deleting it
        const [itemsToRestock] = await db.promise().query(
            'SELECT item_id, quantity FROM sale_items WHERE sale_id = ?', 
            [sale_id]
        );

        // 🚀 2. Loop through and restock each item in your main inventory
        for (let item of itemsToRestock) {
            await db.promise().query(
                'UPDATE item SET stock = stock + ? WHERE item_id = ?',
                [item.quantity, item.item_id]
            );
        }

        // 3. Delete the invoice items and the main invoice
        await db.promise().query('DELETE FROM sale_items WHERE sale_id = ?', [sale_id]);
        await db.promise().query('DELETE FROM sales WHERE sale_id = ?', [sale_id]);

        // Save everything
        await db.promise().query('COMMIT');
        res.status(200).json({ message: "Invoice deleted and all items restocked successfully!" });

    } catch (error) {
        // Undo if something crashed
        await db.promise().query('ROLLBACK');
        console.error("Delete Invoice Error:", error);
        res.status(500).json({ error: "Failed to delete invoice and restock items." });
    }
});

// ==========================================
// 🗜️ EXPORT DAILY INVOICES AS ZIP
// ==========================================
app.get('/invoices/export/zip', verifyToken, async (req, res) => {
    const { startDate, endDate } = req.query; 
    if (!startDate || !endDate) return res.status(400).json({ error: "Start date and End date are required." });

    try {
        const [sales] = await db.promise().query(
            `SELECT s.*, c.customer_name, c.phone_number, c.current_address 
             FROM SALES s 
             LEFT JOIN CUSTOMER c ON s.customer_id = c.customer_id 
             WHERE DATE(s.sale_date) BETWEEN ? AND ?`, 
            [startDate, endDate]
        );

        if (sales.length === 0) {
            return res.status(404).json({ error: "No invoices found for this date range." });
        }

        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=PYSSUM_Invoices_${startDate}_to_${endDate}.zip`);

        const { ZipArchive } = require('archiver');
        const archive = new ZipArchive({ zlib: { level: 9 } });
        
        archive.on('error', function(err) { throw err; });
        archive.pipe(res);

        for (let sale of sales) {
            const [items] = await db.promise().query(
                `SELECT si.*, i.item_name FROM SALES_ITEM si LEFT JOIN ITEM i ON si.item_id = i.item_id WHERE si.sale_id = ?`, 
                [sale.sale_id]
            );

            const doc = new PDFDocument({ margin: 50 });
            const fileName = `Invoice_${sale.invoice_number}.pdf`;
            archive.append(doc, { name: fileName });
            
            // --- TOP LEFT: Header & Dates ---
            doc.font('Times-Bold').fontSize(30).fillColor('#000').text('TAX INVOICE', 50, 50);
            doc.font('Helvetica').fontSize(14).text(`Invoice#: ${sale.invoice_number}`, 50, 85);
            
            const shortDate = new Date(sale.sale_date).toLocaleDateString('en-GB').replace(/\//g, '-');
            doc.text(`Invoice Date: ${shortDate}`, 50, 140);
            doc.text(`Due Date: ${shortDate}`, 50, 160);
            
            // --- TOP RIGHT: Company & Customer Info ---
            doc.font('Helvetica-Bold').fontSize(36).fillColor('#E74C3C').text('PYSSUM', 320, 45);
            doc.font('Helvetica').fontSize(10).fillColor('#000').text('537/8, Puraniya, Sitapur Road,\nLucknow-226020, Uttar Pradesh,\nIndia', 320, 85);
            
            doc.fontSize(12).text(`Billed To: ${sale.customer_name || 'Walk-in Customer'}`, 320, 140);
            doc.text(`Contact Number: ${sale.phone_number || 'N/A'}`, 320, 155);
            doc.text(`Address: ${sale.current_address || ''}`, 320, 170);
            
            // --- TABLE HEADER ---
            doc.roundedRect(50, 210, 500, 30, 8).fill('#000000');
            doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(12);
            doc.text('#', 65, 220);
            doc.text('Item & Description', 100, 220);
            doc.text('MRP', 380, 220);
            doc.text('Total Cost', 450, 220);
            
            // --- TABLE ROWS ---
            let y = 260;
            doc.fillColor('#000000').font('Helvetica').fontSize(12);
            
            items.forEach((item, index) => {
                if (y > 700) { doc.addPage(); y = 50; } 
                
                doc.text((index + 1).toString(), 65, y);
                doc.font('Helvetica-Bold').text(item.item_name || 'Archived Item', 100, y);
                doc.font('Helvetica').text(`Qty: ${item.quantity}`, 100, y + 16);
                
                doc.text(parseFloat(item.sale_rate).toFixed(2), 380, y);
                doc.font('Helvetica-Bold').text(parseFloat(item.amount).toFixed(2), 450, y);
                doc.font('Helvetica'); 
                
                y += 45; 
            });
            
            // --- FOOTER ---
            doc.font('Helvetica-Bold').fontSize(12).text('Authorized Signature:', 50, y + 20);
            doc.fontSize(14).text(`Grand Total: Rs${sale.grand_total}`, 350, y + 20, { align: 'right' });
            
            doc.end();
        }

        await archive.finalize();

    } catch (error) {
        console.error("ZIP Export Error:", error);
        if (!res.headersSent) res.status(500).json({ error: "Failed to generate ZIP file." });
    }
});

// ==========================================
// 📊 FINANCIAL YEAR INVENTORY SNAPSHOT
// ==========================================
app.post('/reports/fy-snapshot', verifyToken, async (req, res) => {
    try {
        // Calculate the current Indian Financial Year (April to March)
        const date = new Date();
        const month = date.getMonth(); // 0 = Jan, 3 = April
        const year = date.getFullYear();
        const financial_year = month >= 3 ? `${year}-${year + 1}` : `${year - 1}-${year}`;

        // Fetch all active items from the main inventory
        const [items] = await db.promise().query('SELECT item_id, stock FROM ITEM WHERE is_active = TRUE');
        
        if (items.length === 0) return res.status(404).json({ error: "No active items found to snapshot." });

        await db.promise().query('START TRANSACTION');

        const insertQuery = `
            INSERT INTO item_yearly_ledger (item_id, financial_year, closing_stock, snapshot_date)
            VALUES (?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE 
            closing_stock = VALUES(closing_stock),
            snapshot_date = NOW()
        `;

        // Loop through all items and save their current stock as the closing stock
        for (let item of items) {
            await db.promise().query(insertQuery, [item.item_id, financial_year, item.stock]);
        }

        await db.promise().query('COMMIT');
        res.status(200).json({ message: `Closing stock successfully recorded for FY ${financial_year}!` });

    } catch (error) {
        await db.promise().query('ROLLBACK');
        console.error("FY Snapshot Error:", error);
        res.status(500).json({ error: "Failed to create FY stock snapshot." });
    }
});

// Fetch the Snapshot History
app.get('/reports/fy-ledger', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT l.financial_year, l.closing_stock, l.snapshot_date, i.item_name, i.barcode, i.unit
            FROM item_yearly_ledger l
            JOIN ITEM i ON l.item_id = i.item_id
            ORDER BY l.financial_year DESC, i.item_name ASC
        `;
        const [results] = await db.promise().query(query);
        res.status(200).json(results);
    } catch (error) {
        console.error("Fetch FY Ledger Error:", error);
        res.status(500).json({ error: "Failed to fetch FY ledger data." });
    }
});

app.use(cors({ origin: 'https://your-vercel-app-url.vercel.app' }));