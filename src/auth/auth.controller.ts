import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator';
import { GetUser } from './decorator/get-user.decorator';
import { AuthDto } from './dto/auth.dto';
import { AcessTokenGuard } from './Guards/access-token.guard';
import { RefreshTokenGuard } from './Guards/refresh-token.guard';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}
    
    @Public()
    @HttpCode(HttpStatus.CREATED)
    @Post('signup')
    signup(@Body() dto: AuthDto): Promise<Tokens>{
        return this.authService.signup(dto)
    }

    @Public()
    @HttpCode(HttpStatus.OK)
    @Post('login')
    login(@Body() dto: AuthDto): Promise<Tokens>{
        return this.authService.login(dto)
    }
    @Public()
    @UseGuards(RefreshTokenGuard)
    @HttpCode(HttpStatus.OK)
    @Post('refresh')
    refresh(@GetUser('sub') userId:number,@GetUser('refreshToken') refreshToken:string){
        return this.authService.refresh(userId,refreshToken)
    }

    @HttpCode(HttpStatus.OK)
    @Post('logout')
    logout(@GetUser('sub') userId:number){
        return this.authService.logout(userId)
    }
}
