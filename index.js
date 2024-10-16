const port = 3000;

const express = require("express");
const app = express();
const path = require("path");
const bodyParser = require("body-parser");
const NodeRSA = require("node-rsa"); 

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const ejs = require("ejs");
app.use(express.static(path.join(__dirname)));
app.set('view engine', 'ejs');

const modulusLength = 512; 
const key = new NodeRSA({ b: modulusLength });

const multer = require("multer");
const upload = multer({ dest: 'uploads/' });

const fs = require("fs");

// ECC imports
const { ec } = require('elliptic');
const ecdh = new ec('secp256k1'); 

const crypto = require('crypto');

// Page linking
app.get("/rsa", (req, res) => {
    res.render("rsa");
});

app.get("/dsa", (req, res) => {
    res.render("dsa");
});

app.get("/dh", (req, res) => {
    res.render("dh");
});

app.get("/ecc", (req, res) => {
    res.render("ecc");
});

app.get("/", (req, res) => {
    res.render("index");
});

// Functional parts for various components

// RSA
app.post("/enRSA", upload.single('fileIp'), (req, res) => {
    const filePath = req.file.path;

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send('Error reading file');
        }

        const encryptedContent = key.encrypt(data, 'base64');
        const encryptedFilePath = path.join(__dirname, 'uploads', 'encrypted_' + req.file.originalname);

        fs.writeFile(encryptedFilePath, encryptedContent, (err) => {
            if (err) {
                return res.status(500).send('Error saving encrypted file');
            }

            res.json({ privateKey: key.exportKey('private'), downloadLink: '/uploads/encrypted_' + req.file.originalname });
        });
    });
});


app.post("/deRSA", upload.single('encryptedFile'), (req, res) => {
    const filePath = req.file.path;

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send('Error reading file');
        }

        try {
            const privateKey = new NodeRSA(req.body.privateKey);
            const decryptedContent = privateKey.decrypt(data, 'utf8');

            const decryptedFilePath = path.join(__dirname, 'uploads', 'decrypted_' + req.file.originalname);
            fs.writeFile(decryptedFilePath, decryptedContent, (err) => {
                if (err) {
                    return res.status(500).send('Error saving decrypted file');
                }
                res.download(decryptedFilePath); 
            });
        } catch (error) {
            return res.status(400).send('Decryption failed: Invalid private key');
        }
    });
});


//DSA
const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
    modulusLength: 2048,
    sign: {
        hash: 'sha256',
    },
    verify: {
        hash: 'sha256',
    },
});


app.post('/sign', (req, res) => {
    const { data } = req.body;

    const signer = crypto.createSign('SHA256');
    signer.update(data);
    signer.end();
    const signature = signer.sign(privateKey, 'hex');

    res.json({ signature });
});


app.post('/verify', (req, res) => {
    const { data, signature } = req.body;

    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);
    verifier.end();
    const isValid = verifier.verify(publicKey, signature, 'hex');

    res.json({ valid: isValid });
});



//DH
function power(a, b, p) {
    if (b === 1) return a;
    return (Math.pow(a, b) % p);
}

app.post('/calculate-keys', (req, res) => {
    const P = 33; 
    const G = 8;  
    const { alicePrivate, bobPrivate } = req.body;

    const x = power(G, alicePrivate, P); 
    const y = power(G, bobPrivate, P);   

    const aliceSecret = power(y, alicePrivate, P); 
    const bobSecret = power(x, bobPrivate, P);     

    res.json({
        aliceSecret,
        bobSecret
    });
});



// ECC functions
function generateKeyPair() {
    const keyPair = ecdh.genKeyPair();
    return {
        publicKey: keyPair.getPublic('hex'),
        privateKey: keyPair.getPrivate('hex')
    };
}

function computeSharedKey(privateKey, otherPublicKey) {
    const key = ecdh.keyFromPrivate(privateKey);
    return key.derive(ecdh.keyFromPublic(otherPublicKey, 'hex').getPublic()).toString(16);
}

// ECC API endpoints
app.post('/generate-keypair', (req, res) => {
    const keyPair = generateKeyPair();
    res.json(keyPair);
});

app.post('/compute-shared-key', (req, res) => {
    const { privateKey, otherPublicKey } = req.body;
    try {
        const sharedKey = computeSharedKey(privateKey, otherPublicKey);
        res.json({ sharedKey });
    } catch (error) {
        res.status(400).json({ error: 'Invalid keys provided.' });
    }
});

// Fundamental components 
app.listen(port, () => {
    console.log(`Server is listening to ${port}`);
});

app.get("*", (req, res) => {
    res.status(400).send("There is no such file.");
});
