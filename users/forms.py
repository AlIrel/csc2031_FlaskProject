from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Email, EqualTo, Length, InputRequired, ValidationError
import re


def character_check(form, field):
    special_char = "<%&"
    for char in field.data:
        if char in special_char:
            raise ValidationError(f"{field} cannot contain the character {char}")

def contain_requirements(form, field):
    requirements = re.compile(r'(?=.*\d)(?=.*[a-z])')
    if not requirements.match(field.data):
        raise ValidationError("Password must contain at least one digit and one lowercase character.")

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(message="You must enter a username."),
                                       Email(message="Username must be an email."),
                                       character_check])
    password = PasswordField(validators=[Length(min=8, max=15, message="Password must be between 8 and 15 characters."),
                                         InputRequired(message="You must enter a password."),
                                         character_check,
                                         contain_requirements])
    confirmPassword = PasswordField(validators=[InputRequired(message="Please repeat the password."),
                                                EqualTo('password', message="Passwords do not match. "
                                                                            "Please check the passwords entered "
                                                                            "are the same.")])
    submit = SubmitField()
