"""Shared Faker for the vendor fakes, with the cyber threat intelligence providers."""

from faker import Faker
from faker_cti import CtiProvider

fake = Faker()
fake.add_provider(CtiProvider)
