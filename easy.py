from dataclasses import dataclass

@dataclass
class User:
	username: str
	email: str
	age: int # Set an int as a string, even if an integer pass, you can use it

	def __post_init__(self):
		self.age = int(self.age)

	def greet(self) -> str:
		return f"Hello, My name is {self.username}. And I'm {self.age} years old. For more details email at: {self.email}. Thank you!"

if __name__ == "__main__":
	user = User(username="IShowSpeed", age="28", email="ishowspeed@issp.com")
	print(user)
	print(user.greet())
