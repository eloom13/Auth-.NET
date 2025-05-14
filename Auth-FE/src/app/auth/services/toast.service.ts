// src/app/shared/services/toast.service.ts
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info' | 'warning';
  autoDismiss: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class ToastService {
  private toasts = new BehaviorSubject<Toast[]>([]);
  private counter = 0;

  constructor() {}

  // Get all active toasts
  get toasts$(): Observable<Toast[]> {
    return this.toasts.asObservable();
  }

  // Show success toast
  success(message: string, autoDismiss: boolean = true): void {
    this.show(message, 'success', autoDismiss);
  }

  // Show error toast
  error(message: string, autoDismiss: boolean = true): void {
    this.show(message, 'error', autoDismiss);
  }

  // Show warning toast
  warning(message: string, autoDismiss: boolean = true): void {
    this.show(message, 'warning', autoDismiss);
  }

  // Show info toast
  info(message: string, autoDismiss: boolean = true): void {
    this.show(message, 'info', autoDismiss);
  }

  // Show toast with given type
  private show(message: string, type: 'success' | 'error' | 'info' | 'warning', autoDismiss: boolean): void {
    const id = ++this.counter;

    const toast: Toast = {
      id,
      message,
      type,
      autoDismiss
    };

    this.toasts.next([...this.toasts.value, toast]);

    if (autoDismiss) {
      setTimeout(() => this.remove(id), 5000);
    }
  }

  // Remove a specific toast by ID
  remove(id: number): void {
    this.toasts.next(this.toasts.value.filter(t => t.id !== id));
  }

  // Clear all toasts
  clear(): void {
    this.toasts.next([]);
  }
}
