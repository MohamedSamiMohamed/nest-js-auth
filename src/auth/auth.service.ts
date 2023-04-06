import { ForbiddenException, Injectable, UseGuards } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt/dist';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport/dist';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthService {
    constructor(private prisma:PrismaService,private jwtService:JwtService,private config:ConfigService){}
    async signup(dto: AuthDto): Promise<Tokens>{
        const hash = await this.hashData(dto.password)
        try{
        const newUser = await this.prisma.user.create({
            data:{
                email: dto.email,
                password: hash
            }
        })
        const tokens = await this.signToken(newUser.id,newUser.email)
        await this.insertRefreshToken(newUser.id,tokens.refresh_token)
        return tokens
    }
    catch(error)
    {
        if (error instanceof Prisma.PrismaClientKnownRequestError){
        console.log("hello")
            if(error.code === 'P2002'){
                throw new ForbiddenException('email alreeady registered before')
            }
        }
        else {
            throw error
        }
    }
    }

    async login(dto: AuthDto): Promise<Tokens>{
        const user = await this.prisma.user.findUnique({
            where:{
                email: dto.email,
            }
        })

        if(!user) throw new ForbiddenException("Credentials incorrect")
        const pwMatches = await argon.verify(user.password,dto.password)
        
        if(!pwMatches) throw new ForbiddenException('credentials incorrect')

        const tokens = await this.signToken(user.id,user.email)
        await this.insertRefreshToken(user.id,tokens.refresh_token)
        return tokens
    }

    async refresh(userId:number,refreshToken:string){

        const user = await this.prisma.user.findUnique({
            where:{
                id: userId,
            }
        })
        if(!user || !user.refreshToken) throw new ForbiddenException("Access Denied")
        
        const refreshTokenMatches = await argon.verify(user.refreshToken,refreshToken)
        if(!refreshTokenMatches)
            throw new ForbiddenException('credentials incorrect')

        const tokens  = await this.signToken(userId,user.email)
        await this.insertRefreshToken(userId,tokens.refresh_token)
        return tokens
        
    }

    async logout(userID: number){
        await this.prisma.user.update({
            where:{
                id: userID
            },
            data:{
                refreshToken: null
            }
        })

        return {
            "message" : "The user has been logged out successfully!"
        }

    }


    async insertRefreshToken(userID:number, refreshToken:string){
        const hash = await this.hashData(refreshToken)
        await this.prisma.user.update({
            where: {
                id: userID
            },
            data: {
                refreshToken: hash
            }
        })
    }

    async hashData(data:string){
        return await argon.hash(data)
    }

    async signToken(userID:Number, email:String): Promise<Tokens> {
        const payload = {
            sub: userID,
            email
        }

        const [accessToken,refreshToken] = await Promise.all([
            this.jwtService.signAsync(payload,{
                expiresIn: '15m',
                secret: this.config.get("ACCESS_TOKEN_SECRET")
            })
            ,
            this.jwtService.signAsync(payload,{
                expiresIn: 60*60*24*7,
                secret: this.config.get("REFRESH_TOKEN_SECRET")
            })
        ])
        

        return {
            access_token: accessToken,
            refresh_token: refreshToken
        }
    }
}
