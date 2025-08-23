# Certificate Validator

A Node.js web application with a user interface for validating X.509 certificates.

## Features

- Upload and validate X.509 certificates (.pem, .crt, .cer, .der formats)
- View certificate details (subject, issuer, validity dates, serial number, thumbprint)
- Check if a certificate is valid or expired
- Clean and responsive user interface

## Prerequisites

- Node.js (v12 or higher)
- npm (v6 or higher)

## Installation

1. Clone this repository:
   ```
   git clone <repository-url>
   cd "Certificate Validator"
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. (Optional) Set the port in a `.env` file (default is 3335):
   ```
   PORT=3335
   ```

## Usage

1. Start the application:
   ```
   npm start
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:3335
   ```
   (or the port you set in `.env`)

3. Upload a certificate file or paste certificate text using the form and click "Validate Certificate".

4. View the validation results and certificate details.

## Supported Certificate Formats

- PEM (.pem)
- X.509 (.crt, .cer)
- DER (.der)

## Project Structure

```
Certificate Validator/
├── index.js              # Main server file
├── package.json          # Project configuration
├── public/               # Static files
│   ├── css/              # CSS stylesheets
│   │   └── style.css     # Main stylesheet
│   └── js/               # Client-side JavaScript
│       └── main.js       # Main JavaScript file
├── views/                # EJS templates
│   └── index.ejs         # Main view template
├── uploads/              # Temporary storage for uploaded certificates
└── .env                  # Environment variables (optional)
```

## Technologies Used

- Node.js - Server-side JavaScript runtime
- Express.js - Web application framework
- EJS - Templating engine
- Multer - Middleware for handling file uploads
- Node-forge - Library for working with certificates

## License

ISC