import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';

interface IPayload {
  name: string;
  email: string;
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const token = request.headers['authorization']?.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('user not authorized!');
    }

    try {
      const payload = this.jwtService.verify<IPayload>(token, {
        algorithms: ['HS256'],
      });
      // TODO: pegar o usuário e colocar na request;
      return true;
    } catch (e) {
      console.error(e);
      throw new UnauthorizedException('invalide user', { cause: e });
    }
  }
}
