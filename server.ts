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

interface AuthUserPayload extends JwtPayload {
  userId?: string | ObjectId;
  email?: string;
  name?: string;
}

interface AuthRequest<Params = Record<string, any>, ResBody = any, ReqBody = any, Query = Record<string, any>>
  extends Request<Params, ResBody, ReqBody, Query> {
  user?: AuthUserPayload;
}

interface UserDocument {
  _id: ObjectId;
  name: string;
  email: string;
  password: string;
  image: string;
  googleId?: string;
  authMethod?: string;
  createdAt: Date;
  updatedAt: Date;
}

interface IdeaDocument {
  _id: ObjectId;
  title: string;
  shortDescription: string;
  detailedDescription: string;
  fullDescription?: string;
  category: string;
  tags: string[];
  imageURL: string;
  location?: string;
  supportNeeded?: string;
  priority?: string;
  estimatedBudget: string;
  targetAudience: string;
  problemStatement: string;
  proposedSolution: string;
  userId: ObjectId;
  userName: string;
  userEmail: string;
  createdAt: Date;
  updatedAt: Date;
  likes: number;
  commentCount: number;
}

interface CommentDocument {
  _id: ObjectId;
  ideaId: ObjectId;
  userId: ObjectId;
  text: string;
  userName?: string;
  userEmail?: string;
  userImage?: string;
  createdAt: Date;
  updatedAt: Date;
}


const verifyToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthUserPayload;
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Forbidden" });
  }
};

async function run() {
  try {
    // await client.connect();

    const db = client.db(DB_NAME);
    const usersCollection = db.collection<UserDocument>("users");
    const communityIdeasCollection = db.collection<IdeaDocument>("community-ideas");
    const commentsCollection = db.collection<CommentDocument>("comments");
    console.log(`Using MongoDB database: ${DB_NAME}`);


    

    
    app.post("/auth/register", async (req: AuthRequest<{ name?: string; email?: string; password?: string; image?: string }>, res) => {
      try {
        const { name, email, password, image } = req.body;

        if (!email || !password || !name) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        if (password.length < 6) {
          return res.status(400).json({ message: "Password must be at least 6 characters" });
        }

        if (!/[A-Z]/.test(password)) {
          return res.status(400).json({ message: "Password must contain at least one uppercase letter" });
        }

        if (!/[a-z]/.test(password)) {
          return res.status(400).json({ message: "Password must contain at least one lowercase letter" });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: "User already exists" });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);
        const newUser: Omit<UserDocument, "_id"> = {
          name,
          email,
          password: hashedPassword,
          image: image || "",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser as UserDocument);

        const token = jwt.sign({ userId: result.insertedId, email, name }, JWT_SECRET, { expiresIn: "7d" });

        res.status(201).json({
          message: "User registered successfully",
          token,
          user: {
            id: result.insertedId,
            name,
            email,
            image: image || "",
          },
        });
      } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Registration failed", error: (error as Error).message });
      }
    });

    app.post("/auth/login", async (req: AuthRequest<{ email?: string; password?: string }>, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res.status(400).json({ message: "Missing email or password" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const isPasswordValid = await bcryptjs.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });

        res.json({
          message: "Login successful",
          token,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        });
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Login failed", error: (error as Error).message });
      }
    });

    app.post("/auth/google", async (req: AuthRequest<{ name?: string; email?: string; image?: string; googleId?: string }>, res) => {
      try {
        const { name, email, image, googleId } = req.body;

        if (!email || !name) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const newUser: Omit<UserDocument, "_id"> = {
            name,
            email,
            password: "",
            image: image || "",
            googleId: googleId || "",
            authMethod: "google",
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await usersCollection.insertOne(newUser as UserDocument);
          user = { ...newUser, _id: result.insertedId };
        } else if (!user.googleId && !user.password) {
          await usersCollection.updateOne({ _id: user._id }, { $set: { googleId: googleId || "", authMethod: "google" } });
        }

        const token = jwt.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });

        res.json({
          message: "Google login successful",
          token,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        });
      } catch (error) {
        console.error("Google OAuth error:", error);
        res.status(500).json({ message: "Google OAuth failed", error: (error as Error).message });
      }
    });

    app.get("/auth/user", verifyToken, async (req: AuthRequest, res) => {
      try {
        const userId = req.user?.userId;
        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const id = typeof userId === "string" ? userId : userId.toString();
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        });
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: "Error fetching user" });
      }
    });

    app.patch("/auth/user", verifyToken, async (req: AuthRequest<{ name?: string; image?: string }>, res) => {
      try {
        const { name, image } = req.body;
        const userId = req.user?.userId;

        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const id = typeof userId === "string" ? userId : userId.toString();
        const updateData: Partial<UserDocument> = {};

        if (name) updateData.name = name;
        if (image) updateData.image = image;
        updateData.updatedAt = new Date();

        const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateData });

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "Profile updated successfully" });
      } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ message: "Error updating profile" });
      }
    });