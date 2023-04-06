import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AcessTokenGuard } from './auth/Guards/access-token.guard';

@Module({
  imports: [
      ConfigModule.forRoot({
        isGlobal: true
      }),
      AuthModule,
      PrismaModule
  ],
  providers:[
    {
      provide: APP_GUARD,
      useClass: AcessTokenGuard
    }
  ]
})
export class AppModule {}
