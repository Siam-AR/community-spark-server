import express, { NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import cors from "cors";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import jwt, { JwtPayload } from "jsonwebtoken";
import bcryptjs from "bcryptjs";

// ===================== COMMIT 1: chore(server): bootstrap express, env, cors, mongo client setup =====================
dotenv.config();

const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error("MONGODB_URI is not defined");
}

const maskedUri = uri.replace(/\/\/([^:]+):([^@]+)@/, "//***:***@");
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";
const DB_NAME = (process.env.MONGODB_DB_NAME || "community-spark").trim();
console.log(`MongoDB URI: ${maskedUri}`);
const CLIENT_URLS = (process.env.CLIENT_URL || process.env.CLIENT_URLS || "")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);

const app = express();
const PORT = Number(process.env.PORT || 5000);

const corsOptions = CLIENT_URLS.length > 0 ? { origin: CLIENT_URLS, credentials: true } : { origin: true, credentials: true };

app.use(cors(corsOptions));
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
