from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List

# Define equivalent Pydantic models for API interactions
class AddressModel(BaseModel):
    street: str
    city: str
    zipcode: str

class UserModel(BaseModel):
    username: str
    email: EmailStr
    addresses: List[AddressModel] = []

    def greet(self) -> str:
        return f"Hi there, I'm {self.username}, with {len(self.addresses)} address(es)."

app = FastAPI()

@app.post("/user")
async def create_user(user: UserModel):
    # Validate and process the user data here, e.g., saving to a database
    return {"message": user.greet()}

# To run the API, use uvicorn:
# uvicorn your_module:app --reload
