export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isActive: boolean;
  createdAt: Date;
  roles: string[];
  isTwoFactorEnabled: boolean;
  emailConfirmed: boolean;
}

export interface RegisterRequest{
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
}
