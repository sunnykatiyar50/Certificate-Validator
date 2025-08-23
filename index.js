const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const forge = require('node-forge');
const fs = require('fs');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3553

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: function(req, file, cb) {
    // Accept only certificate file types
    if (file.mimetype === 'application/x-x509-ca-cert' || 
        file.originalname.endsWith('.pem') || 
        file.originalname.endsWith('.crt') || 
        file.originalname.endsWith('.cer') || 
        file.originalname.endsWith('.der') ||
        file.mimetype === 'application/octet-stream') {
      cb(null, true);
    } else {
      cb(new Error('Only certificate files are allowed!'), false);
    }
  }
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Set up middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Set up EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
  res.render('index', { title: 'Certificate Validator' });
});

// Certificate validation endpoint
app.post('/validate-certificate', upload.single('certificate'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ valid: false, error: 'No certificate file uploaded' });
    }

    const certPath = req.file.path;
    const certData = fs.readFileSync(certPath, 'utf8');

    // Parse certificate
    let cert;
    try {
      cert = forge.pki.certificateFromPem(certData);
    } catch (e) {
      // Try to handle DER format
      try {
        const derData = fs.readFileSync(certPath, 'binary');
        const asn1 = forge.asn1.fromDer(derData);
        cert = forge.pki.certificateFromAsn1(asn1);
      } catch (err) {
        return res.status(400).json({ 
          valid: false, 
          error: 'Invalid certificate format' 
        });
      }
    }

    // Extract certificate details
    const subject = cert.subject.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ');
    const issuer = cert.issuer.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ');
    const validFrom = new Date(cert.validity.notBefore);
    const validTo = new Date(cert.validity.notAfter);
    const serialNumber = cert.serialNumber;

    // Calculate certificate thumbprint (SHA-1)
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha1.create();
    md.update(der);
    const thumbprint = md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();

    // Check if certificate is valid (not expired)
    const now = new Date();
    const isValid = now >= validFrom && now <= validTo;

    // Clean up - delete the uploaded file
    fs.unlinkSync(certPath);

    return res.json({
      valid: isValid,
      details: {
        'Subject': subject,
        'Issuer': issuer,
        'Valid From': validFrom.toLocaleString(),
        'Valid To': validTo.toLocaleString(),
        'Serial Number': serialNumber,
        'Thumbprint': thumbprint,
        'Status': isValid ? 'Valid' : 'Expired'
      }
    });

  } catch (error) {
    console.error('Error validating certificate:', error);
    return res.status(500).json({ 
      valid: false, 
      error: 'Error processing certificate: ' + error.message 
    });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
