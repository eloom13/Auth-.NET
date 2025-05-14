import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-submit-button',
  templateUrl: './submit-button.component.html',
  styleUrls: ['./submit-button.component.scss'],
  standalone: true,
  imports: [CommonModule]
})
export class SubmitButtonComponent {
  @Input() text: string = 'Submit';
  @Input() isLoading: boolean = false;
  @Input() isDisabled: boolean = false;
  @Input() loadingText: string = 'Loading...';
  @Input() fullWidth: boolean = true;
  @Input() buttonType: 'submit' | 'button' = 'submit';
}
