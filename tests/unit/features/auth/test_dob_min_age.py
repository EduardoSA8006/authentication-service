"""Regression tests para L-5: idade mínima em validate_date_of_birth."""
from datetime import date, timedelta

import pytest

from app.features.auth.validators import validate_date_of_birth


class TestMinAge:
    def test_rejects_baby(self):
        with pytest.raises(ValueError, match="Idade mínima"):
            validate_date_of_birth(date.today() - timedelta(days=30))

    def test_rejects_12_year_old(self):
        twelve_years_ago = date.today().replace(year=date.today().year - 12)
        with pytest.raises(ValueError, match="Idade mínima"):
            validate_date_of_birth(twelve_years_ago)

    def test_accepts_exactly_13_years(self):
        thirteen_years_ago = date.today().replace(year=date.today().year - 14)  # safe margin
        validate_date_of_birth(thirteen_years_ago)

    def test_accepts_adult(self):
        validate_date_of_birth(date(1990, 1, 1))
