from dataclasses import dataclass
from datetime import datetime
import random

# Define a data class for a financial transaction.
@dataclass
class Transaction:
    transaction_id: str
    account_number: str
    amount: float
    timestamp: datetime
    description: str

# Define a data class for a user.
@dataclass
class User:
    user_id: str
    name: str
    phone_number: str
    email: str

# Simulated function to send SMS messages.
def send_sms(phone_number: str, message: str) -> None:
    # In a real application, integrate with an SMS API such as Twilio.
    print(f"Sending SMS to {phone_number}:")
    print(message)
    print("-" * 60)

# Function to process a financial transaction and send an SMS notification.
def process_transaction(user: User, transaction: Transaction) -> None:
    # Simulate processing (e.g., deducting from account balance here).
    print(f"Processing transaction {transaction.transaction_id} for user {user.name}...")
    
    # Generate a notification message with the details.
    message = (
        f"Dear {user.name}, your transaction {transaction.transaction_id} of "
        f"${transaction.amount:.2f} has been successfully processed on "
        f"{transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S')}. "
        f"Details: {transaction.description}."
    )
    
    # Send an SMS notification.
    send_sms(user.phone_number, message)

# Example usage.
if __name__ == "__main__":
    # Create an example user.
    user = User(
        user_id="U1001",
        name="Alice",
        phone_number="+1234567890",
        email="alice@example.com"
    )
    
    # Create an example transaction.
    transaction = Transaction(
        transaction_id="T2001",
        account_number="AC12345",
        amount=150.75,
        timestamp=datetime.now(),
        description="Payment for Invoice #INV1001"
    )
    
    # Process the transaction and trigger an SMS notification.
    process_transaction(user, transaction)
