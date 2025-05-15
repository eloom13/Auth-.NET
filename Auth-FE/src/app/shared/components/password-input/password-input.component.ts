import {Component, EventEmitter, Input, Output, Self} from '@angular/core';
import {FormControl, NgControl, ReactiveFormsModule} from '@angular/forms';
import {NgClass, NgIf} from '@angular/common';

@Component({
  selector: 'app-password-input',
  standalone: true,
  imports: [
    ReactiveFormsModule,
    NgClass,
    NgIf
  ],
  templateUrl: './password-input.component.html',
  styleUrl: './password-input.component.css'
})
export class PasswordInputComponent {
  @Input() label: string = 'Password';
  @Input() isVisible: boolean = false;
  @Input() showToggle: boolean = true;
  @Input() showStrengthIndicators: boolean = false;
  @Input() showPasswordMatchError: boolean = false;
  @Output() toggleVisibility = new EventEmitter<void>();

  constructor(@Self() public controlDir: NgControl) {
    this.controlDir.valueAccessor = this;
  }

  writeValue(obj: any): void { }
  registerOnChange(fn: any): void { }
  registerOnTouched(fn: any): void { }

  get control(): FormControl {
    return this.controlDir.control as FormControl;
  }

  onToggleVisibility(): void {
    this.toggleVisibility.emit();
  }

  get showError(): boolean {
    return (this.control?.touched || this.control?.dirty) &&
      (this.control?.invalid || this.showPasswordMatchError);
  }

  get errorMessage(): string {
    if (this.showPasswordMatchError) {
      return 'Passwords do not match';
    }

    const errors = this.control?.errors;
    if (errors) {
      if (errors['required']) return 'Password is required';
      if (errors['minlength']) return `Minimum ${errors['minlength'].requiredLength} characters`;
      if (errors['maxlength']) return `Maximum ${errors['maxlength'].requiredLength} characters`;
      if (errors['hasNumber']) return 'Password must contain at least one number';
      if (errors['hasCapitalCase']) return 'Password must contain at least one uppercase letter';
      if (errors['hasSmallCase']) return 'Password must contain at least one lowercase letter';
      if (errors['hasSpecialCharacters']) return 'Password must contain at least one special character';
    }

    return '';
  }

  // For password strength indicators
  get passwordStrength(): 'weak' | 'medium' | 'strong' | 'empty' {
    if (!this.control?.value) return 'empty';

    const value = this.control.value;
    const hasNumber = /\d/.test(value);
    const hasUpper = /[A-Z]/.test(value);
    const hasLower = /[a-z]/.test(value);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(value);

    const strength = [hasNumber, hasUpper, hasLower, hasSpecial, value.length >= 8].filter(Boolean).length;

    if (strength <= 2) return 'weak';
    if (strength <= 4) return 'medium';
    return 'strong';
  }
}
