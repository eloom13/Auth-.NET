import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { ToastService } from '../../auth/services/toast.service';
import { catchError, throwError } from 'rxjs';

export const errorInterceptorFn: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const toastService = inject(ToastService);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      let errorMessage = 'An error occurred';

      if (error) {
        switch (error.status) {
          case 400:
            if (error.error?.errors?.length) {
              errorMessage = error.error.errors.join(', ');
            } else if (error.error?.message) {
              errorMessage = error.error.message;
            } else {
              errorMessage = 'Bad request';
            }
            break;

          case 401:
            errorMessage = error.error?.message || 'Unauthorized access';
            //router.navigateByUrl('/auth/login');
            break;

          case 403:
            errorMessage = error.error?.message || 'Access forbidden';
            break;

          case 404:
            errorMessage = error.error?.message || 'Resource not found';
            break;

          case 409:
            errorMessage = error.error?.message || 'Conflict occurred';
            break;

          case 429:
            errorMessage = error.error?.message || 'Too many requests, please try again later';
            break;

          case 500:
            errorMessage = 'Server error. Please try again later';
            break;

          default:
            errorMessage = error.error?.message || 'An unexpected error occurred';
            break;
        }

        toastService.error(errorMessage);
      }

      return throwError(() => error);
    })
  );
};

export const jwtInterceptorFn: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem('token');

  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  return next(req);
};
