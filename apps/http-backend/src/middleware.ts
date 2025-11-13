import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "@repo/backend-common/config";

export const userMiddleware = (req: Request, res: Response, next: NextFunction) =>{
    const authHeader = req.headers.authorization;
    if(!authHeader?.startsWith('Bearer ')){
        return res.status(403).json({});
    }
    const token = authHeader.split(' ')[1];
    try{
        const decoded = jwt.verify(token as string, JWT_SECRET as string);
        //@ts-ignore
        req.userId = (decoded as any).userId;
        next();
    } catch (e: unknown) {
        console.error('JWT verification failed:', e);
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
}