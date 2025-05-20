from dataclasses import dataclass

@dataclass
class User:
	username: str
	email: str
	age: int

	def __post_init__(self):
		self.age = int(self.age)

	def greet(self) -> str:
		return f"I'm {self.username} and I'm {self.age} years old. If you're curious about my profile details, email at {self.email}"

if __name__ == "__main__":
	user = User(username="James", email="james@gmail.com", age="19")
	print(user)
	print(user.greet())
