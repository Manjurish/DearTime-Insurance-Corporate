from email.policy import default
from django import forms
from django.forms import TextInput, fields_for_model, widgets
from django.apps import apps
from django.utils.translation import gettext_lazy as _
from collections import OrderedDict
from .models import *
