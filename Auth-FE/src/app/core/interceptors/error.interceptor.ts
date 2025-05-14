// src/app/core/interceptors/error.interceptor.ts
import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';
import { Router } from '@angular/router';
import {ToastService} from '../../auth/services/toast.service';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {

  constructor(
    private router: Router,
    private toastService: ToastService
  ) {}

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error) {
          let errorMessage = 'An error occurred';

          // Handle different error status codes
          switch (error.status) {
            case 400: // Bad Request
              if (error.error?.errors?.length) {
                errorMessage = error.error.errors.join(', ');
              } else if (error.error?.message) {
                errorMessage = error.error.message;
              } else {
                errorMessage = 'Bad request';
              }
              break;

            case 401: // Unauthorized
              errorMessage = error.error?.message || 'Unauthorized access';
              // You might want to redirect to login
              localStorage.removeItem('token');
              this.router.navigateByUrl('/auth/login');
              break;

            case 403: // Forbidden
              errorMessage = error.error?.message || 'Access forbidden';
              break;

            case 404: // Not Found
              errorMessage = error.error?.message || 'Resource not found';
              break;

            case 409: // Conflict
              errorMessage = error.error?.message || 'Conflict occurred';
              break;

            case 429: // Too Many Requests
              errorMessage = error.error?.message || 'Too many requests, please try again later';
              break;

            case 500: // Server Error
              errorMessage = 'Server error. Please try again later';
              break;

            default:
              errorMessage = error.error?.message || 'An unexpected error occurred';
              break;
          }

          this.toastService.error(errorMessage);
        }

        return throwError(() => error);
      })
    );
  }
}
