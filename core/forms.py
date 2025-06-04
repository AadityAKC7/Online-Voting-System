from django import forms
from .models import Voter, Candidate
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
import re
from django.shortcuts import render, redirect
from .models import Candidate, Position

class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True)

    class Meta:
        model = Voter
        fields = ['first_name', 'last_name', 'email', 'national_id','phone', 'password']

    def clean_first_name(self):
        data = self.cleaned_data['first_name']
        if not data.isalpha():
            raise ValidationError("First name must contain only letters.")
        return data

    def clean_last_name(self):
        data = self.cleaned_data['last_name']
        if not data.isalpha():
            raise ValidationError("Last name must contain only letters.")
        return data

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Password must be at least 8 characters and contain a special character.")
        return password

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if not phone.isdigit() or len(phone) != 10:
            raise ValidationError("Phone number must be exactly 10 digits.")
        return phone

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm = cleaned_data.get("confirm_password")
        if password and confirm and password != confirm:
            raise ValidationError("Passwords do not match.")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user
class EmailLoginForm(AuthenticationForm):
    username = forms.EmailField(label='Email', widget=forms.EmailInput(attrs={'autofocus': True}))
class SimpleLoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

class VoterEditForm(forms.ModelForm):
    class Meta:
        model = Voter
        fields = ['first_name', 'last_name', 'email', 'phone', 'profile_picture']


class CandidateForm(forms.ModelForm):
    class Meta:
        model = Candidate
        fields = ['name', 'image', 'position']

class PositionForm(forms.ModelForm):
    class Meta:
        model = Position
        fields = ['name', 'max_votes', 'priority']

class VoterForm(forms.ModelForm):
    class Meta:
        model = Voter
        fields = ['first_name', 'last_name', 'email', 'national_id', 'is_email_verified']

