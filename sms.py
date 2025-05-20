from dataclasses import dataclass

@dataclass
class User:
	username: str
	email: str
	admin: str
	xenomi: str
	age: int # Convert it into an integer
	phone_number: int # Set an int as a string, even if an integer pass, you can use it

	def __post_init__(self):
		self.age = int(self.age)

	def __post_init__(self):
		self.phone_number = int(self.phone_number)

	def greet(self) -> str:
		return f"Dear {self.username}, Your age {self.age} you are not qualified for creating an account with us, prehaps you slightly mistaken when registering. However, If you wish you were mistakenly, feel free to contact our support team at: {self.xenomi}. Thank you!"

if __name__ == "__main__":
	user = User(username="Ryan Willian", email="ryanwil@gmail.com", admin="xenomi@support.com", age="20", phone_number="+144504040500", xenomi="xenomi@age.com")
	print(user)
	print(user.greet())
