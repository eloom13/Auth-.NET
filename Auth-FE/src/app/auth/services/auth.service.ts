import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, map, tap } from 'rxjs';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment';
import { User } from '../models/user';
import { ApiResponse } from '../models/api-response';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private baseUrl = `${environment.apiUrl}/auth`;
  private currentUserSource = new BehaviorSubject<User | null>(null);
  currentUser$ = this.currentUserSource.asObservable();

  constructor(private http: HttpClient, private router: Router) {
    //this.loadCurrentUser();
  }

  // Load user from local storage

  loadCurrentUser() {
    /*const token = localStorage.getItem('token');
    if (!token) {
      this.currentUserSource.next(null);
      return;
    }
    */

    /*
    this.getCurrentUser().subscribe({
      next: user => {
        if (user) {
          this.currentUserSource.next(user);
        }
      },
      error: () => {
        this.currentUserSource.next(null);
        localStorage.removeItem('token');
      }
    });
    */

  }

  // Register new user
  register(values: any): Observable<ApiResponse<any>> {
    return this.http.post<ApiResponse<any>>(`${this.baseUrl}/register`, values)
      .pipe(
        tap(response => {
          if (response.success && response.data.token) {
            //localStorage.setItem('token', response.data.token);
            this.loadCurrentUser();
          }
        })
      );
  }
/*
  // Login user
  login(values: any): Observable<ApiResponse<any>> {
    return this.http.post<ApiResponse<any>>(`${this.baseUrl}/login`, values)
      .pipe(
        tap(response => {
          if (response.success && response.data.token) {
            localStorage.setItem('token', response.data.token);
            this.loadCurrentUser();
          }
        })
      );
  }

  // Logout user
  logout(): Observable<ApiResponse<boolean>> {
    return this.http.post<ApiResponse<boolean>>(`${this.baseUrl}/logout`, {})
      .pipe(
        tap(() => {
          localStorage.removeItem('token');
          this.currentUserSource.next(null);
          this.router.navigateByUrl('/auth/login');
        })
      );
  }

  // Get current authenticated user
  getCurrentUser(): Observable<User | null> {
    return this.http.get<ApiResponse<User>>(`${this.baseUrl}/current-user`)
      .pipe(
        map(response => {
          if (response.success) {
            return response.data;
          }
          return null;
        })
      );
  }

  // Check if email is available
  checkEmail(email: string): Observable<{available: boolean, message: string}> {
    return this.http.post<{available: boolean, message: string}>(`${this.baseUrl}/check-email`, { email });
  }

  // Check if username is available
  checkUsername(username: string): Observable<{available: boolean, message: string}> {
    return this.http.post<{available: boolean, message: string}>(`${this.baseUrl}/check-username`, { username });
  }

  // Resend email confirmation
  resendConfirmationEmail(email: string): Observable<ApiResponse<boolean>> {
    return this.http.post<ApiResponse<boolean>>(`${this.baseUrl}/resend-confirmation-email`, { email });
  }

  // Verify two-factor authentication code
  verifyTwoFactor(email: string, code: string): Observable<ApiResponse<any>> {
    return this.http.post<ApiResponse<any>>(`${this.baseUrl}/two-factor`, { email, twoFactorCode: code })
      .pipe(
        tap(response => {
          if (response.success && response.data.token) {
            localStorage.setItem('token', response.data.token);
            this.loadCurrentUser();
          }
        })
      );
  }

  // Setup two-factor authentication
  setupTwoFactor(): Observable<ApiResponse<boolean>> {
    return this.http.post<ApiResponse<boolean>>(`${this.baseUrl}/setup-2fa`, {});
  }

  // Generate two-factor authentication code
  generateTwoFactorCode(): Observable<ApiResponse<string>> {
    return this.http.get<ApiResponse<string>>(`${this.baseUrl}/generate-2fa-code`);
  }

  // Get current user value
  get currentUserValue(): User | null {
    return this.currentUserSource.value;
  }

  // Check if user is authenticated
  isAuthenticated(): boolean {
    return !!this.currentUserValue;
  }
  */
}
