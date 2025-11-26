import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

const upload = multer({ dest: "uploads/" });

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const API_TOKEN = process.env.API_TOKEN;

// AES encryption
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(ENCRYPTION_KEY, "utf8"),
    iv
  );
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  return {
    iv: iv.toString("hex"),
    content: encrypted,
    tag: cipher.getAuthTag().toString("hex"),
  };
}

// AES decryption
function decrypt(hash) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(ENCRYPTION_KEY, "utf8"),
    Buffer.from(hash.iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(hash.tag, "hex"));

  let decrypted = decipher.update(hash.content, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Upload route
app.post("/upload", upload.single("script"), (req, res) => {
  if (req.headers.authorization !== API_TOKEN)
    return res.status(401).json({ error: "Unauthorized" });

  const file = req.file;
  const content = fs.readFileSync(file.path, "utf8");

  const encrypted = encrypt(content);
  const fileId = crypto.randomBytes(12).toString("hex");

  fs.writeFileSync(
    `uploads/${fileId}.json`,
    JSON.stringify(encrypted, null, 2)
  );

  res.json({
    message: "File uploaded & encrypted successfully",
    raw_url: `${req.protocol}://${req.get("host")}/raw/${fileId}`,
  });

  fs.unlinkSync(file.path); // delete temp upload
});

// Raw access route
app.get("/raw/:id", (req, res) => {
  const token = req.query.token;

  if (token !== API_TOKEN)
    return res.status(404).send("404 SKID NOT FOUND");

  const filePath = `uploads/${req.params.id}.json`;

  if (!fs.existsSync(filePath))
    return res.status(404).send("404 SKID NOT FOUND");

  const encryptedData = JSON.parse(fs.readFileSync(filePath));
  const decrypted = decrypt(encryptedData);

  res.type("text/plain").send(decrypted);
});

// Uploader page
app.get("/uploader.html", (req, res) => {
  res.sendFile(path.join(process.cwd(), "uploader.html"));
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
