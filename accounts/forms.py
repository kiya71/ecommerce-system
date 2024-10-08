from django import forms
from .models import Account
from django.contrib import messages



class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder':' Enter Password', 'class':'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': ' Confirm Password'}))
    class Meta:
        model = Account
        fields = ['first_name', 'last_name','phone_number', 'email', 'password']



    def clean(self):
        cleaned_data = super(RegistrationForm, self).clean()
        password = self.cleaned_data.get('password')
        confirm_password = self.cleaned_data.get('confirm_password')


        if password != confirm_password:
            raise forms.ValidationError("Passwords must match")




    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].widget.attrs['placeholder'] = 'Enter first Name'
        self.fields['last_name'].widget.attrs['placeholder'] = 'Enter last Name'
        self.fields['email'].widget.attrs['placeholder'] = 'Enter Email Addess'
        self.fields['phone_number'].widget.attrs['placeholder'] = 'Enter phone number'
        for field in self.fields:
            self.fields[field].widget.attrs['class'] = 'form-control'




