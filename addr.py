from dataclasses import dataclass, field
from typing import List

@dataclass
class Address:
	street: str
	city: str
	zipcode: str

@dataclass
class User:
	username:str
	email: str
	addresses: List[Address] = field(default_factory=list)

	def add_address(self, address: Address):
		self.addresses.append(address)

# Example Usage
user = User(username="James", email="james@gmail.com")
user.add_address(Address(street="223", city="California", zipcode="644"))
print(user)
