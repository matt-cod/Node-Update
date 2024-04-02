import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import { ObjectId } from 'mongodb';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Joi from 'joi';

// Initialize Express app
const app = express();

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Define MongoDB collections for room types and rooms respectively
let roomTypesCollection: any[] = [];
let roomsCollection: any[] = [];
let usersCollection: any[] = [];

// Define roles
const ROLES = {
    GUEST: 'guest',
    ADMIN: 'admin'
};

// Define schema for user validation
const userSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid(...Object.values(ROLES)).required()
});

// POST endpoint/API for user registration
app.post('/api/v1/users/register', validateRequest(userSchema), async (req: Request, res: Response) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { username, password: hashedPassword, role };
        usersCollection.push(user);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST endpoint/API for user login
app.post('/api/v1/users/login', async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;
        const user = usersCollection.find(user => user.username === username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ username: user.username, role: user.role }, 'secretkey');
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Middleware for authentication
function authenticateToken(req: Request, res: Response, next: NextFunction) {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    jwt.verify(token, 'secretkey', (err: any, user: any) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.user = user;
        next();
    });
}

// Middleware for authorization
function authorize(role: string) {
    return (req: Request, res: Response, next: NextFunction) => {
        if (req.user && req.user.role === role) {
            next();
        } else {
            res.status(403).json({ error: 'Forbidden' });
        }
    };
}

// Validation middleware
function validateRequest(schema: Joi.ObjectSchema<any>) {
    return (req: Request, res: Response, next: NextFunction) => {
        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }
        next();
    };
}

// POST endpoint/API for storing room types
app.post('/api/v1/rooms-types', authenticateToken, authorize(ROLES.ADMIN), (req: Request, res: Response) => {
    // Implementation remains the same
});

// PATCH endpoint for editing a room by its id
app.patch('/api/v1/rooms/:roomId', authenticateToken, authorize(ROLES.ADMIN), (req: Request, res: Response) => {
    // Implementation remains the same
});

// DELETE endpoint for deleting a room by its id
app.delete('/api/v1/rooms/:roomId', authenticateToken, authorize(ROLES.ADMIN), (req: Request, res: Response) => {
    // Implementation remains the same
});

// Start server on port 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
