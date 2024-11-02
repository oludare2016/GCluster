from django import forms
from .models import CustomUser
from django.core.exceptions import ValidationError


class UserCreationForm(forms.ModelForm):
    """
    A form that creates a user, with no privileges, from the given email and
    password.
    """

    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(
        label="Password confirmation", widget=forms.PasswordInput
    )

    class Meta:
        """
        Meta class for UserCreationForm
        """

        model = CustomUser
        fields = (
            "email",
            "name",
            "user_type",
            "profile_picture",
            "phone_number",
            "address",
            "country",
            "status",
            "is_active",
            "is_staff",
            "password1",
            "password2",
        )

    def clean_password2(self):
        """
        Verify that the two password entries match.
        :return:
        """
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        """
        Save the provided password in hashed format.
        :param commit:
        :return:
        """
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """
    A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """

    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput,
        required=False,
        help_text="Leave blank if you don't want to change the password.",
    )
    password2 = forms.CharField(
        label="Password confirmation",
        widget=forms.PasswordInput,
        required=False,
        help_text="Enter the same password as before, for verification.",
    )

    class Meta:
        """
        Meta class for UserChangeForm
        """

        model = CustomUser
        fields = (
            "email",
            "name",
            "user_type",
            "profile_picture",
            "phone_number",
            "address",
            "country",
            "state",
            "city",
            "status",
            "is_active",
            "is_staff",
            "is_superuser",
            "password1",
            "password2",
        )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 or password2:
            if password1 != password2:
                raise ValidationError("Passwords do not match.")
            if password1:
                self.instance.set_password(password1)
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        # Password is already set in clean method
        if commit:
            user.save()
        return user
