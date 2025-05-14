// src/app/auth/validators/custom-validators.ts
import { AbstractControl, FormGroup, ValidationErrors, ValidatorFn } from '@angular/forms';

export class CustomValidators {
  /**
   * Validator for password pattern matching
   * @param regex The regular expression to test
   * @param error The error object to return if validation fails
   */
  static patternValidator(regex: RegExp, error: ValidationErrors): ValidatorFn {
    return (control: AbstractControl): ValidationErrors | null => {
      if (!control.value) {
        // If control is empty, return no error
        return null;
      }

      // Test the value of the control against the regex supplied
      const valid = regex.test(control.value);

      // If true, return no error, else return error passed in the second parameter
      return valid ? null : error;
    };
  }

  /**
   * Validator to check if password and confirm password match
   */
  static passwordMatchValidator(formGroup: FormGroup): ValidationErrors | null {
    const password = formGroup.get('password');
    const confirmPassword = formGroup.get('confirmPassword');

    if (!password || !confirmPassword) {
      return null;
    }

    // Check if both fields have values and if they match
    if (confirmPassword.value && password.value !== confirmPassword.value) {
      formGroup.setErrors({ NoPasswordMatch: true });
      return { NoPasswordMatch: true };
    }

    return null;
  }
}
