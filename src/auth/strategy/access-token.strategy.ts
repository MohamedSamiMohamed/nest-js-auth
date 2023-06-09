import { Injectable } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"
import { PassportStrategy } from "@nestjs/passport"
import { ExtractJwt, Strategy } from "passport-jwt"
import { PrismaService } from "src/prisma/prisma.service"
import { Request } from "express"
@Injectable()
export class AcessTokenStrategy extends PassportStrategy(Strategy,'jwt') {
    constructor(config: ConfigService, private prisma:PrismaService){
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.get("ACCESS_TOKEN_SECRET"),
            passReqToCallback: true
        })
    }

    async validate(req:Request,payload:{sub:number,email:string}){
        const accessToken = req.get('Authorization').replace('Bearer','').trim()
        return {
            ...payload,
            accessToken
        }
    }
}