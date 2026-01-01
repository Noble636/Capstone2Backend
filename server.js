// --- IMPORTS & CONSTANTS ---
const express = require('express');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const upload = multer();
const crypto = require('crypto');
const ExcelJS = require('exceljs');
dotenv.config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';
const IV_LENGTH = 16;
const app = express();
const port = process.env.PORT || 5000;

// --- MIDDLEWARE ---
app.use(express.json());
app.use(cors());

// --- DB POOL ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// --- UTILS ---
const handleDatabaseError = (res, err) => {
    console.error('Database error:', err);
    res.status(500).json({ message: 'Database error occurred' });
};

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const DEVELOPER_TOKEN = 'Token';

// --- ENCRYPTION HELPERS ---
function encryptDeterministic(text) {
    if (!text) return '';
    const iv = Buffer.alloc(IV_LENGTH, 0);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}
function encrypt(text) {
    if (!text) return '';
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}
function decryptDeterministic(encrypted) {
    if (!encrypted) return '';
    const iv = Buffer.alloc(IV_LENGTH, 0);
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
function decrypt(text) {
    if (!text) return '';
    let parts = text.split(':');
    let iv = Buffer.from(parts.shift(), 'hex');
    let encryptedText = parts.join(':');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// --- ROUTES ---
// Get all complaints for a specific tenant (for EditComplaints and ComplaintStatus)
app.get('/api/tenant/complaints', async (req, res) => {
    const { tenantId } = req.query;
    if (!tenantId) {
        return res.status(400).json({ message: 'Missing tenantId' });
    }
    try {
        // Fetch complaints for this tenant
        const [complaints] = await db.execute(
            'SELECT complaint_id, complaint_text, complaint_date, submitted_at, status, admin_message FROM tenant_complaints WHERE tenant_id = ? ORDER BY submitted_at DESC',
            [tenantId]
        );
        if (complaints.length > 0) {
            // Fetch images for these complaints
            const ids = complaints.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            let imagesByComplaint = {};
            if (ids.length > 0) {
                const [imagesRows] = await db.execute(
                    `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                    ids
                );
                imagesByComplaint = {};
                for (const row of imagesRows) {
                    const base64 = row.image_data ? row.image_data.toString('base64') : null;
                    const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                    if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                    imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
                }
            }
            for (const c of complaints) c.images = imagesByComplaint[c.complaint_id] || [];
        }
        res.status(200).json(complaints);
    } catch (error) {
        console.error('Error fetching tenant complaints:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/register', async (req, res) => {
    const { fullName, email, username, password, adminToken } = req.body;

    if (!fullName || !email || !username || !password || !adminToken) {
        return res.status(400).json({ message: 'Full Name, Email, Username, Password, and Admin Token are required.' });
    }

    try {
        console.log('[REGISTER] Username:', username);
        const encryptedUsername = encryptDeterministic(username);
        console.log('[REGISTER] Encrypted Username:', encryptedUsername);
        const encryptedEmail = encryptDeterministic(email);
        const [existingAdmin] = await db.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);
        if (existingAdmin.length > 0) {
            return res.status(409).json({ message: 'Username already exists for an admin account.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedAdminToken = await bcrypt.hash(adminToken, 10);
        const [result] = await db.execute(
            'INSERT INTO admins (full_name, email, username, password, admin_token) VALUES (?, ?, ?, ?, ?)',
            [fullName, encryptedEmail, encryptedUsername, hashedPassword, hashedAdminToken]
        );

        res.status(201).json({ message: 'Admin account created successfully!' });
    } catch (error) {
        console.error('Error during admin registration:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

        try {
            console.log('[LOGIN] Username:', username);
            const encryptedUsername = encryptDeterministic(username);
            console.log('[LOGIN] Encrypted Username:', encryptedUsername);
            const [admins] = await db.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);

        if (admins.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const admin = admins[0];
        const passwordMatch = await bcrypt.compare(password, admin.password);

        if (passwordMatch) {
            res.status(200).json({ message: 'Admin login successful!', adminId: admin.admin_id, fullName: admin.full_name });
        } else {
            res.status(401).json({ message: 'Invalid username or password.' });
        }
    } catch (error) {
        console.error('Error during admin login:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/register', async (req, res) => {
    const { username, password, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber } = req.body;

    if (!username || !password || !fullName) {
        return res.status(400).json({ message: 'Username, password, and full name are required' });
    }

    try {
        // Encrypt sensitive fields
        const encryptedUsername = encryptDeterministic(username);
        const encryptedEmail = encryptDeterministic(email);
        const encryptedContactNumber = contactNumber ? encrypt(contactNumber) : null;
        const encryptedEmergencyContactNumber = emergencyContactNumber ? encrypt(emergencyContactNumber) : null;

        const [existingUser] = await db.execute('SELECT * FROM tenants WHERE username = ?', [encryptedUsername]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.execute(
            'INSERT INTO tenants (username, password, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [encryptedUsername, hashedPassword, fullName, encryptedEmail, encryptedContactNumber, apartmentId, emergencyContact, encryptedEmergencyContactNumber]
        );

        res.status(201).json({ message: 'Tenant registered successfully', tenantId: result.insertId });
    } catch (error) {
        console.error('Error during registration:', error);
        handleDatabaseError(res, error);
    }
});


app.post('/api/tenant/forgot-password/verify-username', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ message: 'Username is required.' });
    }

    try {
        const encryptedUsername = encryptDeterministic(username);
        const [user] = await db.execute('SELECT * FROM tenants WHERE username = ?', [encryptedUsername]);
        if (user.length === 0) {
            return res.status(404).json({ message: 'Username not found.' });
        }
        // Decrypt fields as needed before sending to frontend
        const userDetails = {
            username: username,
            email: decryptDeterministic(user[0].email),
            full_name: decryptDeterministic(user[0].full_name),
            apartment_id: user[0].apartment_id
        };
        // ...send OTP, etc...
        res.status(200).json({ userDetails, message: 'An OTP has been sent to your registered email address.' });
    } catch (error) {
        console.error('Error verifying tenant username:', error);
        res.status(500).json({ message: 'Failed to connect to the server.' });
    }
});

app.post('/api/tenant/forgot-password/verify-otp', async (req, res) => {
    const { username, otp } = req.body;

    if (!username || !otp) {
        return res.status(400).json({ message: 'Username and OTP are required' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND otp = ? AND expires_at > NOW()',
            [username, otp]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/forgot-password/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
        return res.status(400).json({ message: 'Username and new password are required' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND expires_at > NOW()',
            [username]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'OTP not verified or expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE tenants SET password = ? WHERE username = ?', [hashedPassword, username]);

        await db.execute('DELETE FROM password_reset_otps WHERE username = ?', [username]);

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error during password reset:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/submit-complaint', upload.array('images', 3), async (req, res) => {
    const { tenantId, complaint, date } = req.body;

    if (!tenantId || !complaint || !date) {
        return res.status(400).json({ message: 'Tenant ID, complaint, and date are required' });
    }

    try {
        const [result] = await db.execute(
            'INSERT INTO tenant_complaints (tenant_id, complaint_text, complaint_date, status, admin_message) VALUES (?, ?, ?, ?, ?)',
            [tenantId, complaint, date, 'Pending', null]
        );

        const complaintId = result.insertId;
        if (req.files && req.files.length > 0) {
            const files = req.files.slice(0, 3);
            let order = 1;
            for (const file of files) {
                await db.execute(
                    'INSERT INTO complaint_images (complaint_id, image_data, mime_type, filename, image_order) VALUES (?, ?, ?, ?, ?)',
                    [complaintId, file.buffer, file.mimetype || 'image/jpeg', file.originalname || null, order]
                );
                order++;
            }
        }

        res.status(201).json({ message: 'Complaint submitted successfully', complaintId });
    } catch (error) {
        console.error('Error submitting complaint:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const encryptedUsername = encryptDeterministic(username);
        const [tenants] = await db.execute('SELECT tenant_id, username, password, full_name, apartment_id FROM tenants WHERE username = ?', [encryptedUsername]);
        if (tenants.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const tenant = tenants[0];
        const passwordMatch = await bcrypt.compare(password, tenant.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        res.status(200).json({
            message: 'Login successful',
            userId: tenant.tenant_id,
            fullName: tenant.full_name,
            apartmentId: tenant.apartment_id,
        });
    } catch (error) {
        console.error('Error during login:', error);
        handleDatabaseError(res, error);
    }
});

app.put('/api/tenant/complaints/:complaintId', upload.array('images', 3), async (req, res) => {
    const { complaintId } = req.params;
    const { complaintText } = req.body;

    if (!complaintText) {
        return res.status(400).json({ message: 'Complaint text is required for updating.' });
    }

    try {
        await db.execute(
            'UPDATE tenant_complaints SET complaint_text = ? WHERE complaint_id = ?',
            [complaintText, complaintId]
        );

        if (req.files && req.files.length > 0) {
            await db.execute('DELETE FROM complaint_images WHERE complaint_id = ?', [complaintId]);

            const files = req.files.slice(0, 3);
            let order = 1;
            for (const file of files) {
                await db.execute(
                    'INSERT INTO complaint_images (complaint_id, image_data, mime_type, filename, image_order) VALUES (?, ?, ?, ?, ?)',
                    [complaintId, file.buffer, file.mimetype || 'image/jpeg', file.originalname || null, order]
                );
                order++;
            }
        }

        res.status(200).json({ message: 'Complaint updated successfully.' });
    } catch (error) {
        console.error('Error updating tenant complaint:', error);
        handleDatabaseError(res, error);
    }
});

app.delete('/api/tenant/complaints/:complaintId', async (req, res) => {
    const { complaintId } = req.params;
    try {
        const [result] = await db.execute('DELETE FROM tenant_complaints WHERE complaint_id = ?', [complaintId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Complaint not found.' });
        }
        res.status(200).json({ message: 'Complaint deleted successfully.' });
    } catch (error) {
        console.error('Error deleting complaint:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/complaints/active', async (req, res) => {
    try {
        const [activeComplaints] = await db.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.submitted_at, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            "WHERE tc.status IS NULL OR tc.status = 'Pending' " +
            'ORDER BY tc.submitted_at DESC'
        );
        if (activeComplaints.length > 0) {
            const ids = activeComplaints.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await db.execute(
                `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                ids
            );
            const imagesByComplaint = {};
            for (const row of imagesRows) {
                const base64 = row.image_data ? row.image_data.toString('base64') : null;
                const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
            }
            for (const c of activeComplaints) c.images = imagesByComplaint[c.complaint_id] || [];
        }

        res.status(200).json(activeComplaints);
    } catch (error) {
        console.error('Error fetching active complaints for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/complaints/log', async (req, res) => {
    try {
        const [complaintsLog] = await db.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.submitted_at, tc.status, tc.admin_message, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            "WHERE tc.status = 'Attended' OR tc.status = 'Declined' " +
            'ORDER BY tc.submitted_at DESC'
        );
        if (complaintsLog.length > 0) {
            const ids = complaintsLog.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await db.execute(
                `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                ids
            );
            const imagesByComplaint = {};
            for (const row of imagesRows) {
                const base64 = row.image_data ? row.image_data.toString('base64') : null;
                const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
            }
            for (const c of complaintsLog) c.images = imagesByComplaint[c.complaint_id] || [];
        }

        res.status(200).json(complaintsLog);
    } catch (error) {
        console.error('Error fetching complaints log for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.put('/api/admin/complaints/:complaintId', async (req, res) => {
    const { complaintId } = req.params;
    const { status, adminMessage } = req.body;
    const adminId = null;

    if (!status || (status !== 'Attended' && status !== 'Declined')) {
        return res.status(400).json({ message: 'Invalid status provided. Must be "Attended" or "Declined".' });
    }

    try {
        await db.query('START TRANSACTION');

        const [currentComplaint] = await db.execute(
            'SELECT status FROM tenant_complaints WHERE complaint_id = ? FOR UPDATE',
            [complaintId]
        );

        if (currentComplaint.length === 0) {
            await db.query('ROLLBACK');
            return res.status(404).json({ message: `Complaint ${complaintId} not found.` });
        }
        const oldStatus = currentComplaint[0].status;

        const [updateResult] = await db.execute(
            'UPDATE tenant_complaints SET status = ?, admin_message = ? WHERE complaint_id = ?',
            [status, adminMessage, complaintId]
        );

        if (updateResult.affectedRows > 0) {
            await db.execute(
                'INSERT INTO complaint_admin_actions (complaint_id, admin_id, action_type, old_status, new_status, action_message) VALUES (?, ?, ?, ?, ?, ?)',
                [complaintId, adminId, 'Status Update', oldStatus, status, adminMessage]
            );
            await db.query('COMMIT');
        res.status(200).json({ message: `Complaint ${complaintId} marked as ${status}.` });
        } else {
            await db.query('ROLLBACK');
            res.status(500).json({ message: 'Failed to update complaint status.' });
        }
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error updating complaint status:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/visitor-logs', async (req, res) => {
    try {
        const [visitorLogs] = await db.execute(
            'SELECT log_id, tenant_id, apartment_id, unit_owner_name, visitor_names, purpose, visit_date, time_in, time_out, created_at ' +
            'FROM visitor_logs ' +
            'ORDER BY created_at DESC'
        );
        res.status(200).json(visitorLogs);
    } catch (error) {
        console.error('Error fetching visitor logs for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/tenants', async (req, res) => {
    try {
        const [tenants] = await db.execute(
            'SELECT tenant_id, username, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number, created_at ' +
            'FROM tenants ' +
            'ORDER BY created_at DESC'
        );
        // Decrypt sensitive fields for display
        const decryptedTenants = tenants.map(t => ({
            ...t,
            username: t.username ? decryptDeterministic(t.username) : '',
            email: t.email ? decryptDeterministic(t.email) : '',
            contact_number: t.contact_number ? decrypt(t.contact_number) : '',
            emergency_contact_number: t.emergency_contact_number ? decrypt(t.emergency_contact_number) : ''
        }));
        res.status(200).json(decryptedTenants);
    } catch (error) {
        console.error('Error fetching tenants for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/profile/:tenantId', async (req, res) => {
    const { tenantId } = req.params;

    if (!tenantId) {
        return res.status(400).json({ message: 'Tenant ID is required.' });
    }

    try {
        const [tenantRows] = await db.execute(
            'SELECT tenant_id, username, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number, password FROM tenants WHERE tenant_id = ?',
            [tenantId]
        );
        if (tenantRows.length === 0) {
            return res.status(404).json({ message: 'Tenant not found.' });
        }
        const tenant = tenantRows[0];
        // Decrypt sensitive fields for display
        tenant.username = decryptDeterministic(tenant.username);
        tenant.email = decryptDeterministic(tenant.email);
        tenant.contact_number = tenant.contact_number ? decrypt(tenant.contact_number) : '';
        tenant.emergency_contact_number = tenant.emergency_contact_number ? decrypt(tenant.emergency_contact_number) : '';
        res.status(200).json(tenant);
    } catch (error) {
        console.error('Error fetching tenant profile:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/profile/:adminId', async (req, res) => {
    const { adminId } = req.params;
    if (!adminId) return res.status(400).json({ message: 'Admin ID is required.' });
    try {
        const [rows] = await db.execute('SELECT admin_id, username, full_name, email FROM admins WHERE admin_id = ?', [adminId]);
        if (rows.length === 0) return res.status(404).json({ message: 'Admin not found.' });
        const admin = rows[0];
        admin.username = decryptDeterministic(admin.username);
        admin.email = decryptDeterministic(admin.email);
        res.status(200).json(admin);
    } catch (err) {
        console.error('Error fetching admin profile:', err);
        handleDatabaseError(res, err);
    }
});

app.put('/api/admin/profile/:adminId', async (req, res) => {
    const { adminId } = req.params;
    let { username, fullName, email, currentPassword, newPassword, adminToken } = req.body;

    if (!fullName) return res.status(400).json({ message: 'Full name is required.' });

    try {
        // ENCRYPT SENSITIVE FIELDS BEFORE SAVING
        const encryptedUsername = username ? encryptDeterministic(username) : undefined;
        const encryptedEmail = email ? encryptDeterministic(email) : undefined;

        // ...existing logic for password check, etc...

        const setParts = ['full_name = ?', 'email = ?'];
        const params = [fullName, encryptedEmail];

        if (username) {
            setParts.unshift('username = ?');
            params.unshift(encryptedUsername);
        }

        if (newPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            setParts.push('password = ?');
            params.push(hashedPassword);
        }
        if (adminToken) {
            const hashedAdminToken = await bcrypt.hash(adminToken, 10);
            setParts.push('admin_token = ?');
            params.push(hashedAdminToken);
        }

        const updateQuery = `UPDATE admins SET ${setParts.join(', ')} WHERE admin_id = ?`;
        params.push(adminId);

        const [result] = await db.execute(updateQuery, params);

        if (result.affectedRows === 0) return res.status(404).json({ message: 'Admin not found or no changes made.' });

        res.status(200).json({ message: 'Admin account updated successfully!' });
    } catch (err) {
        console.error('Error updating admin profile:', err);
        handleDatabaseError(res, err);
    }
});

app.put('/api/tenant/profile/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    let { username, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber, currentPassword, newPassword } = req.body;

    if (!fullName || !contactNumber || !apartmentId) {
        return res.status(400).json({ message: 'Full Name, Contact Number, and Apartment ID are required.' });
    }

    try {
        // ENCRYPT SENSITIVE FIELDS BEFORE SAVING
        const encryptedUsername = username ? encryptDeterministic(username) : undefined;
        const encryptedEmail = email ? encryptDeterministic(email) : undefined;
        const encryptedContactNumber = contactNumber ? encrypt(contactNumber) : null;
        const encryptedEmergencyContact = emergencyContact ? encrypt(emergencyContact) : null;
        const encryptedEmergencyContactNumber = emergencyContactNumber ? encrypt(emergencyContactNumber) : null;

        const setParts = [
            'full_name = ?',
            'email = ?',
            'contact_number = ?',
            'apartment_id = ?',
            'emergency_contact = ?',
            'emergency_contact_number = ?'
        ];
        const params = [
            fullName,
            encryptedEmail,
            encryptedContactNumber,
            apartmentId,
            encryptedEmergencyContact,
            encryptedEmergencyContactNumber
        ];

        // If username changed, update it
        if (username) {
            setParts.unshift('username = ?');
            params.unshift(encryptedUsername);
        }

        // If password changed, update it
        if (newPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            setParts.push('password = ?');
            params.push(hashedPassword);
        }

        const updateQuery = `UPDATE tenants SET ${setParts.join(', ')} WHERE tenant_id = ?`;
        params.push(tenantId);

        const [result] = await db.execute(updateQuery, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Tenant not found or no changes made.' });
        }

        res.status(200).json({ message: 'Account updated successfully!' });
    } catch (error) {
        console.error('Error updating tenant profile:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/forgot-password/verify-token', async (req, res) => {
    const { token } = req.body;
    try {
        // Check developer token
        if (token === process.env.DEVELOPER_TOKEN || token === 'Token') {
            return res.json({ message: 'Token verified.' });
        }
        // Check all admin tokens in the database
        const [rows] = await db.query('SELECT admin_token FROM admins');
        for (const row of rows) {
            if (await bcrypt.compare(token, row.admin_token)) {
                return res.json({ message: 'Token verified.' });
            }
        }
        return res.status(401).json({ message: 'Invalid token.' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error.' });
    }
});

app.post('/api/admin/forgot-password/verify-username', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ message: 'Username is required.' });
    }

    try {
        const encryptedUsername = encryptDeterministic(username);
        const [admin] = await db.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);
        if (admin.length === 0) {
            return res.status(404).json({ message: 'Admin username not found.' });
        }
        // Decrypt fields as needed before sending to frontend
        const adminDetails = {
            username: username,
            email: decryptDeterministic(admin[0].email),
            full_name: decryptDeterministic(admin[0].full_name)
        };
        // ...send OTP, etc...
        res.status(200).json({ adminDetails, message: 'An OTP has been sent to your registered email address.' });
    } catch (error) {
        console.error('Error verifying admin username:', error);
        res.status(500).json({ message: 'Failed to connect to the server.' });
    }
});

app.post('/api/admin/forgot-password/verify-otp', async (req, res) => {
    const { username, otp } = req.body;

    if (!username || !otp) {
        return res.status(400).json({ message: 'Username and OTP are required.' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND otp = ? AND expires_at > NOW()',
            [username, otp]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        res.status(200).json({ message: 'OTP verified successfully.' });
    } catch (error) {
        console.error('Error verifying admin OTP:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/forgot-password/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
        return res.status(400).json({ message: 'Username and new password are required.' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND expires_at > NOW()',
            [username]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'OTP verification required or expired.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE admins SET password = ? WHERE username = ?', [hashedPassword, username]);

        await db.execute('DELETE FROM password_reset_otps WHERE username = ?', [username]);

        res.status(200).json({ message: 'Admin password reset successfully!' });
    } catch (error) {
        console.error('Error during admin password reset:', error);
        handleDatabaseError(res, error);
    }
});

app.delete('/api/admin/tenants/:tenantId', async (req, res) => {
    const { tenantId } = req.params;

    if (!tenantId) {
        return res.status(400).json({ message: 'Tenant ID is required to delete an account.' });
    }

    try {
        await db.query('START TRANSACTION');

        await db.execute('DELETE FROM tenant_complaints WHERE tenant_id = ?', [tenantId]);

        await db.execute('DELETE FROM visitor_logs WHERE tenant_id = ?', [tenantId]);

        const [tenantResult] = await db.execute('DELETE FROM tenants WHERE tenant_id = ?', [tenantId]);

        if (tenantResult.affectedRows === 0) {
            await db.query('ROLLBACK');
            return res.status(404).json({ message: `Tenant account with ID '${tenantId}' not found.` });
        }

        await db.query('COMMIT');

        res.status(200).json({ message: `Tenant account with ID '${tenantId}' and associated data deleted successfully.` });

    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error deleting tenant account and associated data:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/verify-admin-token', async (req, res) => {
    const { adminId, adminToken } = req.body;
    const DEVELOPER_TOKEN = 'Token'; // Make sure this matches your hardcoded value

    if (!adminId || !adminToken) {
        return res.status(400).json({ valid: false, message: 'Admin ID and token required.' });
    }

    // Allow developer token
    if (adminToken === DEVELOPER_TOKEN) {
        return res.json({ valid: true });
    }

    try {
        const [rows] = await db.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
        if (rows.length === 0) {
            return res.status(404).json({ valid: false, message: 'Admin not found.' });
        }
        const isValid = await bcrypt.compare(adminToken, rows[0].admin_token);
        if (isValid) {
            return res.json({ valid: true });
        } else {
            return res.json({ valid: false, message: 'Invalid admin token.' });
        }
    } catch (err) {
        console.error('Error verifying admin token:', err);
        res.status(500).json({ valid: false, message: 'Server error.' });
    }
});


app.listen(port, () => {
    const baseUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;
    console.log(`Server is running on ${baseUrl}`);
});

app.post('/api/tenant/register', async (req, res) => {
    const { username, password, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber } = req.body;

    // Log the incoming registration request (excluding password)
    console.log('[REGISTER] Incoming tenant registration:', {
        username,
        fullName,
        email,
        contactNumber,
        apartmentId,
        emergencyContact,
        emergencyContactNumber
    });

    if (!username || !password || !fullName || !email || !apartmentId) {
        console.error('[REGISTER] Missing required fields:', { username, passwordPresent: !!password, fullName, email, apartmentId });
        return res.status(400).json({ message: 'Required fields are missing.' });
    }

    try {
        // Encrypt username and email deterministically for searchability
        const encryptedUsername = encryptDeterministic(username);
        const encryptedEmail = encryptDeterministic(email);
        // Encrypt contact numbers (not deterministic, not for search)
        const encryptedContactNumber = contactNumber ? encrypt(contactNumber) : null;
        const encryptedEmergencyContact = emergencyContact ? encrypt(emergencyContact) : null;
        const encryptedEmergencyContactNumber = emergencyContactNumber ? encrypt(emergencyContactNumber) : null;

        // Check if username already exists (search by encrypted username)
        const [existingTenant] = await db.execute('SELECT * FROM tenants WHERE username = ?', [encryptedUsername]);
        if (existingTenant.length > 0) {
            console.warn('[REGISTER] Username already exists:', username);
            return res.status(409).json({ message: 'Username already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO tenants (username, password, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [encryptedUsername, hashedPassword, fullName, encryptedEmail, encryptedContactNumber, apartmentId, encryptedEmergencyContact, encryptedEmergencyContactNumber]
        );

        console.log('[REGISTER] Tenant registered successfully:', username);
        res.status(201).json({ message: 'Tenant registered successfully!' });
    } catch (error) {
        console.error('[REGISTER] Error during tenant registration:', error && error.stack ? error.stack : error);
        handleDatabaseError(res, error);
    }
});

// Get all visitor logs for a specific tenant
app.get('/api/tenant/visitor-logs/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    if (!tenantId) {
        return res.status(400).json({ message: 'Missing tenantId' });
    }
    try {
        const [rows] = await db.query(
            'SELECT log_id, visit_date, visitor_names, purpose, time_in, time_out FROM visitor_logs WHERE tenant_id = ? ORDER BY visit_date DESC, log_id DESC',
            [tenantId]
        );
        res.json(rows);
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

// Set time out for a visitor log
app.put('/api/tenant/visitor-logs/:logId/timeout', async (req, res) => {
    const { logId } = req.params;
    const { timeOut } = req.body;
    if (!logId || !timeOut) {
        return res.status(400).json({ message: 'Missing logId or timeOut' });
    }
    try {
        // Only allow setting time_out if not already set
        const [rows] = await db.query('SELECT time_out FROM visitor_logs WHERE log_id = ?', [logId]);
        if (!rows.length) {
            return res.status(404).json({ message: 'Visitor log not found' });
        }
        if (rows[0].time_out) {
            return res.status(400).json({ message: 'Time out already set for this log' });
        }
        await db.query('UPDATE visitor_logs SET time_out = ? WHERE log_id = ?', [timeOut, logId]);
        res.json({ message: 'Time out updated successfully' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.post('/api/tenant/submit-visitor', async (req, res) => {
    const { tenantId, fullName, apartmentId, visitorNames, visitDate, timeIn, purpose } = req.body;

    if (!tenantId || !fullName || !apartmentId || !visitorNames || !visitDate || !timeIn) {
        return res.status(400).json({ message: 'All visitor log fields are required.' });
    }

    try {
        const [result] = await db.execute(
            'INSERT INTO visitor_logs (tenant_id, apartment_id, unit_owner_name, visitor_names, purpose, visit_date, time_in) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [tenantId, apartmentId, fullName, visitorNames, purpose || null, visitDate, timeIn]
        );
        res.status(201).json({ message: 'Visitor log submitted successfully!', logId: result.insertId });
    } catch (error) {
        console.error('Error submitting visitor log:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/export-complaints', async (req, res) => {
    try {
        const [complaints] = await db.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.complaint_date, tc.status, tc.admin_message ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            'ORDER BY tc.complaint_date DESC'
        );

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Tenant_Complaints_Report'); // <-- Sheet name

        worksheet.columns = [
            { header: 'Complaint ID', key: 'complaint_id', width: 15 },
            { header: 'Tenant Name', key: 'full_name', width: 25 },
            { header: 'Apartment ID', key: 'apartment_id', width: 15 },
            { header: 'Complaint', key: 'complaint_text', width: 40 },
            { header: 'Date', key: 'complaint_date', width: 20 },
            { header: 'Status', key: 'status', width: 15 },
            { header: 'Admin Message', key: 'admin_message', width: 30 }
        ];

        complaints.forEach(row => worksheet.addRow(row));

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=Tenant_Complaint_Reports.xlsx'); // <-- File name

        await workbook.xlsx.write(res);
        res.end();
    } catch (error) {
        console.error('Error exporting complaints:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/export-visitor-logs', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const adminId = req.body.adminId;
  if (!token || !(await isValidAdminToken(token, adminId))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const [logs] = await db.execute('SELECT * FROM visitor_logs');
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Tenant_Visitor_Report'); // <-- Sheet name
  worksheet.columns = [
    { header: 'Log ID', key: 'log_id' },
    { header: 'Tenant Owner', key: 'unit_owner_name' },
    { header: 'Apartment ID', key: 'apartment_id' },
    { header: 'Visitor(s)', key: 'visitor_names' },
    { header: 'Purpose', key: 'purpose' },
    { header: 'Date of Visit', key: 'visit_date' },
    { header: 'Time In', key: 'time_in' },
    { header: 'Time Out', key: 'time_out' }
  ];
  logs.forEach(log => worksheet.addRow(log));
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename=Tenant_Visitor_Reports.xlsx'); // <-- File name
  await workbook.xlsx.write(res);
  res.end();
});

app.post('/api/admin/export-accounts', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const adminId = req.body.adminId;
  console.log('[EXPORT ACCOUNTS] token:', token, 'adminId:', adminId);

  if (!token) {
    return res.status(401).json({ message: 'Missing token' });
  }

  if (token === DEVELOPER_TOKEN || (process.env.DEV_TOKEN && token === process.env.DEV_TOKEN)) {
    // proceed
  } else {
    if (!adminId) {
      return res.status(401).json({ message: 'Missing adminId' });
    }
    try {
      const [rows] = await db.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
      if (!rows.length) {
        return res.status(401).json({ message: 'Admin not found' });
      }
      const adminTokenHash = rows[0].admin_token;
      const isMatch = await bcrypt.compare(token, adminTokenHash);
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid token' });
      }
    } catch (err) {
      console.error('Error validating admin token:', err);
      return res.status(500).json({ message: 'Error validating token' });
    }
  }

  try {
    const [tenants] = await db.execute('SELECT * FROM tenants');
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Tenant_Account_Reports');
    worksheet.columns = [
      { header: 'Tenant ID', key: 'tenant_id' },
      { header: 'Full Name', key: 'full_name' },
      { header: 'Username', key: 'username' },
      { header: 'Email', key: 'email' },
      { header: 'Contact Number', key: 'contact_number' },
      { header: 'Apartment ID', key: 'apartment_id' },
      { header: 'Emergency Contact', key: 'emergency_contact' },
      { header: 'Emergency Contact Number', key: 'emergency_contact_number' }
    ];
    tenants.forEach(tenant => worksheet.addRow(tenant));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Tenant_Account_Reports.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch (error) {
    console.error('Error exporting accounts:', error);
    res.status(500).json({ message: 'Error exporting accounts' });
  }
});

async function isValidAdminToken(token, adminId) {
  if (token === DEVELOPER_TOKEN || token === process.env.DEV_TOKEN) return true;
  if (!adminId) return false;
  try {
    const [rows] = await db.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
    if (rows.length === 0) return false;
    return await bcrypt.compare(token, rows[0].admin_token);
  } catch (err) {
    console.error('Error validating admin token:', err);
    return false;
  }
}

// POST endpoint for admin to add a unit
app.post('/api/admin/available-units', upload.array('images', 5), async (req, res) => {
  const { unitName, description, price } = req.body;
  const files = req.files || [];

  if (!unitName || !price) {
    return res.status(400).json({ message: 'Unit name and price are required.' });
  }

  try {
    // Insert unit info (no image fields here)
    const [result] = await db.query(
      'INSERT INTO available_units (title, description, price) VALUES (?, ?, ?)',
      [unitName, description, price]
    );
    const unitId = result.insertId;

    // Insert each image into unit_images
    for (const file of files) {
      await db.query(
        'INSERT INTO unit_images (unit_id, image_data, image_type) VALUES (?, ?, ?)',
        [unitId, file.buffer, file.mimetype]
      );
    }

    res.json({ success: true, unitId });
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

// Replace your current GET /api/available-units with this:
app.get('/api/available-units', async (req, res) => {
  try {
    const [units] = await db.query(
      `SELECT u.*, 
        (SELECT image_data FROM unit_images WHERE unit_id = u.unit_id LIMIT 1) AS image_data,
        (SELECT image_type FROM unit_images WHERE unit_id = u.unit_id LIMIT 1) AS image_type
       FROM available_units u
       WHERE u.hidden = 0
       ORDER BY u.created_at DESC`
    );
    // Convert image_data to base64
    const result = units.map(u => ({
      ...u,
      images: u.image_data
        ? [{ dataUri: `data:${u.image_type};base64,${u.image_data.toString('base64')}` }]
        : []
    }));
    res.json(result);
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// POST new inquiry
app.post('/api/unit-inquiries', async (req, res) => {
  const { unit_id, sender_name, message } = req.body;
  if (!unit_id || !sender_name || !message) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  try {
    await db.query(
      'INSERT INTO unit_inquiries (unit_id, sender_name, message, sender) VALUES (?, ?, ?, ?)',
      [unit_id, sender_name, message, 'tenant']
    );
    res.status(201).json({ message: 'Inquiry sent' });
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// GET: Get all inquiries for a user by name
app.get('/api/unit-inquiries', async (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ message: 'Name is required.' });
  try {
    const [rows] = await db.query(
      'SELECT * FROM unit_inquiries WHERE sender_name = ? ORDER BY created_at',
      [name]
    );
    res.json(rows);
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// GET: Admin fetches all inquiries
app.get('/api/admin/inbox', async (req, res) => {
  const sql = `
    SELECT m.*, u.title AS unit_name
    FROM unit_inquiry_messages m
    JOIN available_units u ON m.unit_id = u.unit_id
    WHERE 
      (m.sender_type = 'tenant')
      OR
      (m.sender_type = 'admin' AND m.recipient_name IS NOT NULL)
    ORDER BY m.unit_id, m.created_at DESC
  `;
  try {
    const [results] = await db.query(sql);
    res.json(results);
  } catch (err) {
    console.error('INBOX SQL ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST: Admin replies to an inquiry
app.post('/api/admin/inbox/reply', async (req, res) => {
  const { inquiryId, reply } = req.body;
  if (!inquiryId || !reply) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  try {
    // Save reply in the same inquiry row (add a 'reply' column in unit_inquiries if not present)
    await db.query('UPDATE unit_inquiries SET reply = ? WHERE inquiry_id = ?', [reply, inquiryId]);
    // Optionally, you can also insert a new row for each reply if you want a threaded chat
    res.status(200).json({ message: 'Reply sent' });
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// GET: Inquiry history by unit ID and sender name
app.get('/api/unit-inquiries/history', async (req, res) => {
  const { unit_id, sender_name } = req.query;
  if (!unit_id || !sender_name) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  try {
    const [rows] = await db.query(
      'SELECT * FROM unit_inquiries WHERE unit_id = ? AND sender_name = ? ORDER BY created_at ASC',
      [unit_id, sender_name]
    );
    res.json(rows);
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// POST new inquiry message
app.post('/api/unit-inquiry-messages', async (req, res) => {
  const { unit_id, sender_name, sender_type, message, recipient_name } = req.body;
  if (!unit_id || !sender_name || !sender_type || !message) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  try {
    await db.query(
      `INSERT INTO unit_inquiry_messages (unit_id, sender_name, sender_type, message, recipient_name)
       VALUES (?, ?, ?, ?, ?)`,
      [unit_id, sender_name, sender_type, message, recipient_name || null]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Get all inquiry messages for a unit and sender
app.get('/api/unit-inquiry-messages', async (req, res) => {
  const { unit_id, sender_name } = req.query;
  if (!unit_id || !sender_name) {
    return res.status(400).json({ message: 'Missing unit_id or sender_name' });
  }
  try {
    const [messages] = await db.query(
      `SELECT * FROM unit_inquiry_messages
       WHERE unit_id = ?
         AND (
           (sender_type = 'tenant' AND sender_name = ?)
           OR
           (sender_type = 'admin' AND recipient_name = ?)
         )
       ORDER BY created_at ASC`,
      [unit_id, sender_name, sender_name]
    );
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/available-units/:unitId', async (req, res) => {
  const { unitId } = req.params;
  try {
    await db.query('DELETE FROM available_units WHERE unit_id = ?', [unitId]);
    await db.query('DELETE FROM unit_images WHERE unit_id = ?', [unitId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

// Add to your server.js (backend)
app.delete('/api/admin/conversation', async (req, res) => {
  const { unit_id, tenant_name } = req.body;
  if (!unit_id || !tenant_name) return res.status(400).json({ message: 'Missing unit_id or tenant_name' });
  try {
    await db.execute(
      'DELETE FROM unit_inquiry_messages WHERE unit_id = ? AND sender_name = ?',
      [unit_id, tenant_name]
    );
    res.status(200).json({ message: 'Conversation deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});

app.post('/api/admin/send-message', (req, res) => {
  const { unit_id, message, sender_name, recipient_name } = req.body;
  const sender_type = 'admin';
  const sql = `
    INSERT INTO unit_inquiry_messages (unit_id, message, sender_name, sender_type, recipient_name, created_at)
    VALUES (?, ?, ?, ?, ?, NOW())
  `;
  db.query(sql, [unit_id, message, sender_name, sender_type, recipient_name], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ success: true });
  });
});

const fetchConversations = () => {
  fetch('https://tenantportal-backend.onrender.com/api/admin/inbox')
    .then(res => {
      if (!res.ok) {
        throw new Error('Failed to fetch conversations');
      }
      return res.json();
    })
    .then(data => {
      if (!Array.isArray(data)) {
        setConversations([]);
        return;
      }
      // ...existing grouping logic...
      const tenantPairs = new Set();
      data.forEach(msg => {
        if (msg.sender_type && msg.sender_type.trim().toLowerCase() === 'tenant') {
          tenantPairs.add(`${msg.unit_id}|||${msg.sender_name}`);
        }
      });

      const convList = [];
      tenantPairs.forEach(pair => {
        const [unit_id, tenant_name] = pair.split('|||');
        const convMsgs = data.filter(
          m =>
            m.unit_id == unit_id &&
            (m.sender_name === tenant_name || (m.sender_type && m.sender_type.trim().toLowerCase() === 'admin'))
        );
        if (convMsgs.length > 0) {
          const latest = convMsgs.reduce((a, b) =>
            new Date(a.created_at) > new Date(b.created_at) ? a : b
          );
          convList.push({
            ...latest,
            sender_name: tenant_name,
            last_message: latest.message,
            unit_id,
          });
        }
      });

      convList.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setConversations(convList);
    })
    .catch(err => {
      setConversations([]);
      // Optionally, set an error state to show a message in the UI
      console.error('Error fetching conversations:', err);
    });
};

// POST: Create a reservation and hide the unit
app.post('/api/unit-reservations', async (req, res) => {
  const { unit_id, name, contact, other_info } = req.body;
  if (!unit_id || !name || !contact) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }
  try {
    // Insert reservation
    await db.query(
      'INSERT INTO unit_reservations (unit_id, name, contact, other_info) VALUES (?, ?, ?, ?)',
      [unit_id, name, contact, other_info || null]
    );
    // Hide the unit (set hidden=1)
    await db.query('UPDATE available_units SET hidden=1 WHERE unit_id = ?', [unit_id]);
    res.json({ message: 'Reservation successful and unit hidden.' });
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// GET: Admin fetches all reservations
app.get('/api/admin/reservations', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT r.*, u.title, u.price,
        (SELECT image_data FROM unit_images WHERE unit_id = r.unit_id LIMIT 1) AS image_data,
        (SELECT image_type FROM unit_images WHERE unit_id = r.unit_id LIMIT 1) AS image_type
       FROM unit_reservations r
       LEFT JOIN available_units u ON r.unit_id = u.unit_id
       ORDER BY r.created_at DESC`
    );
    const reservations = rows.map(row => ({
      ...row,
      image: row.image_data
        ? `data:${row.image_type};base64,${row.image_data.toString('base64')}`
        : null
    }));
    res.json(reservations);
  } catch (err) {
    console.error(err); // Add this for debugging
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Cancel reservation and unhide the unit
app.delete('/api/admin/reservations/:reservationId', async (req, res) => {
  const { reservationId } = req.params;
  try {
    // Get the unit_id before deleting
    const [[reservation]] = await db.query('SELECT unit_id FROM unit_reservations WHERE reservation_id = ?', [reservationId]);
    if (!reservation) return res.status(404).json({ message: 'Reservation not found.' });

    // Delete the reservation
    await db.query('DELETE FROM unit_reservations WHERE reservation_id = ?', [reservationId]);
    // Unhide the unit
    await db.query('UPDATE available_units SET hidden=0 WHERE unit_id = ?', [reservation.unit_id]);
    res.json({ message: 'Reservation cancelled and unit is now available.' });
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

app.get('/api/admin/export-reservations', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT r.*, u.title, u.price
       FROM unit_reservations r
       LEFT JOIN available_units u ON r.unit_id = u.unit_id
       ORDER BY r.created_at DESC`
    );

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Reservations');

    worksheet.columns = [
      { header: 'Reservation ID', key: 'reservation_id', width: 15 },
      { header: 'Unit', key: 'title', width: 20 },
      { header: 'Price', key: 'price', width: 12 },
      { header: 'Name', key: 'name', width: 20 },
      { header: 'Contact', key: 'contact', width: 20 },
      { header: 'Other Info', key: 'other_info', width: 30 },
      { header: 'Date', key: 'created_at', width: 22 }
    ];

    rows.forEach(row => {
      worksheet.addRow({
        reservation_id: row.reservation_id,
        title: row.title,
        price: row.price,
        name: row.name,
        contact: row.contact,
        other_info: row.other_info,
        created_at: row.created_at
      });
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Reservations_Report.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to generate report.' });
  }
});