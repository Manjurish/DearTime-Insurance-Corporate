from django.conf import settings
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from datetime import datetime
import six

class TokenGenerator(PasswordResetTokenGenerator):

    def make_token(self, user):
        """
        Return a token that can be used once to do a password reset
        for the given user.
        """
        return self._make_token_with_timestamp(user, self._num_days(self._today()))

    def check_token(self, user, token, check_level):
        """
        Check that a password reset token is correct for a given user.
        """
        if not (user and token):
            return False
        # Parse the token
        try:
            ts_b36, hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False

        # Check the timestamp is within limit. Timestamps are rounded to
        # midnight (server time) providing a resolution of only 1 day. If a
        # link is generated 5 minutes before midnight and used 6 minutes later,
        # that counts as 1 day. Therefore, PASSWORD_RESET_TIMEOUT_DAYS = 1 means
        # "at least 1 day, could be up to 2."
        if check_level == "1":
            if (int(self._num_days(self._today())) - ts) > settings.PASSWORD_RESET_TIMEOUT_DAYS:
                return False
        elif check_level =="2":
            if(int(self._num_days(self._today())) - ts) > settings.PASSWORD_LINK_EXPIRED:
                return False
                
        return True

    def _make_token_with_timestamp(self, user, timestamp):
        # timestamp is number of days since 2001-1-1.  Converted to
        # base 36, this gives us a 3 digit string until about 2121
        ts_b36 = int_to_base36(int(timestamp))
        hash = salted_hmac(
            self.key_salt,
            self._make_hash_value(user, int(timestamp)),
            secret=self.secret,
        ).hexdigest()[::2]  # Limit to 20 characters to shorten the URL.
        return "%s-%s" % (ts_b36, hash)

    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + user.password + six.text_type(timestamp) 
        )
    
    def _num_days(self, dt):
        return (str(dt.year) + str(dt.month).zfill(2) + str(dt.day).zfill(2) + str(dt.hour).zfill(2) + str(dt.minute).zfill(2))

    def _today(self):
        # Used for mocking in tests
        return datetime.today()

password_reset_token = TokenGenerator()