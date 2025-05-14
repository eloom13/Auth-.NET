import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { CommonModule } from '@angular/common';
import {AuthService} from '../services/auth.service';
import {ToastService} from '../services/toast.service';
import {CustomValidators} from '../validators/custom-validators';
import {TextInputComponent} from '../../shared/components/text-input/text-input.component';
import {PasswordInputComponent} from '../../shared/components/password-input/password-input.component';
import {SubmitButtonComponent} from '../../shared/components/submit-button/submit-button.component';


@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss'],
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink, TextInputComponent, PasswordInputComponent, SubmitButtonComponent]
})
export class RegisterComponent implements OnInit {
  registerForm!: FormGroup;
  showPassword: boolean = false;
  showConfirmPassword: boolean = false;
  isLoading: boolean = false;
  emailError: string = '';
  usernameError: string = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private toastService: ToastService
  ) {}

  ngOnInit(): void {
    this.initForm();
    //this.setupFormListeners();
  }

  initForm(): void {
    this.registerForm = this.fb.group({
      firstName: [null, [Validators.required, Validators.minLength(2), Validators.maxLength(20)]],
      lastName: [null, [Validators.required, Validators.minLength(2), Validators.maxLength(20)]],
      username: [null, [Validators.required, Validators.minLength(5), Validators.maxLength(20)]],
      email: [null, [Validators.required, Validators.email]],
      password: [null, [
        Validators.required,
        Validators.minLength(8),
        Validators.maxLength(64),
        CustomValidators.patternValidator(/\d/, { hasNumber: true }),
        CustomValidators.patternValidator(/[A-Z]/, { hasCapitalCase: true }),
        CustomValidators.patternValidator(/[a-z]/, { hasSmallCase: true }),
        CustomValidators.patternValidator(/[!@#$%^&*(),.?":{}|<>]/, { hasSpecialCharacters: true }),
      ]],
      confirmPassword: [null, Validators.required],
    }, { validators: CustomValidators.passwordMatchValidator });
  }

  /*
  setupFormListeners(): void {
    this.registerForm.get('email')?.valueChanges.subscribe(email => {
      if (email && this.registerForm.get('email')?.valid) {
        this.checkEmail(email);
      } else {
        this.emailError = '';
      }
    });

    this.registerForm.get('username')?.valueChanges.subscribe(username => {
      if (username && this.registerForm.get('username')?.valid) {
        this.checkUsername(username);
      } else {
        this.usernameError = '';
      }
    });
  }
  */

  /*
  checkEmail(email: string): void {
    this.authService.checkEmail(email).subscribe({
      next: (response) => {
        if (!response.available) {
          this.emailError = response.message;
        } else {
          this.emailError = '';
        }
      },
      error: (err) => {
        console.error('Error checking email', err);
      }
    });
  }

  checkUsername(username: string): void {
    this.authService.checkUsername(username).subscribe({
      next: (response) => {
        if (!response.available) {
          this.usernameError = response.message;
        } else {
          this.usernameError = '';
        }
      },
      error: (err) => {
        console.error('Error checking username', err);
      }
    });
  }
  */

  togglePasswordVisibility(): void {
    this.showPassword = !this.showPassword;
  }

  toggleConfirmPasswordVisibility(): void {
    this.showConfirmPassword = !this.showConfirmPassword;
  }

  onSubmit(): void {
    if (this.registerForm.valid && !this.emailError && !this.usernameError) {
      this.isLoading = true;
      const formData = this.registerForm.value;

      this.authService.register(formData).subscribe({
        next: (response) => {
          this.toastService.success('Registration successful! Please check your email to verify your account.');
          this.router.navigate(['/auth/verify-email']);
        },
        error: (error) => {
          this.isLoading = false;
        },
        complete: () => {
          this.isLoading = false;
        }
      });
    } else {
      this.markFormGroupTouched(this.registerForm);
      this.toastService.error('Please fix the errors in the form before submitting.');
    }
  }

  // Helper method to mark all controls as touched
  markFormGroupTouched(formGroup: FormGroup) {
    Object.values(formGroup.controls).forEach(control => {
      control.markAsTouched();

      if (control instanceof FormGroup) {
        this.markFormGroupTouched(control);
      }
    });
  }
}
