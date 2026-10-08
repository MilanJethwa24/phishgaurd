"""Train a TF-IDF + Logistic Regression phishing classifier and save it with joblib."""
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")

# 1 = phishing, 0 = legitimate
PHISHING = [
    "Your account has been suspended. Verify your identity immediately by clicking this link.",
    "URGENT: Your bank account will be locked within 24 hours. Confirm your password now.",
    "Congratulations! You have won a $1000 gift card. Claim your prize now.",
    "We detected unusual sign-in activity. Login here to secure your account immediately.",
    "Your PayPal account is limited. Update your billing information to restore access.",
    "Dear customer, your package could not be delivered. Pay the small fee to reschedule.",
    "Final notice: your invoice is overdue. Download the attached file to avoid legal action.",
    "You are selected for a tax refund. Submit your credit card details to receive payment.",
    "Act now! Limited time offer, verify your SSN to receive your free reward.",
    "Your Apple ID was locked for security reasons. Click here to unlock it.",
    "Netflix: your payment failed. Update your card details within 48 hours or lose access.",
    "Security alert: confirm your login credentials to avoid permanent account closure.",
    "I am a prince and need your help to transfer $10 million. Send your bank details.",
    "Your mailbox is full. Click the link and enter your password to increase storage.",
    "Microsoft support: your computer is infected. Call this number and give remote access.",
    "Wire transfer needed urgently, CEO request, keep this confidential and act today.",
    "Your Amazon order has a problem. Verify your account information to avoid cancellation.",
    "Claim your bitcoin reward now. Send a small deposit to unlock your winnings.",
    "Unusual activity detected on your card. Reply with your PIN to confirm.",
    "Your password expires today. Reset it immediately using the link below.",
    "You have an unclaimed inheritance. Provide your personal details to process it.",
    "Free iPhone winner! Click now and enter your shipping and payment info.",
    "IRS notice: you owe back taxes. Pay with gift cards immediately to avoid arrest.",
    "Verify your email account now or it will be deleted permanently.",
    "Dear user, your account login was attempted. Confirm identity at the secure portal now.",
    "Your Office 365 session expired, sign in again to view the shared document.",
    "Bank of America: suspicious transaction. Click to verify or your account will be frozen.",
    "Get rich quick! Guaranteed investment returns, act fast, limited spots.",
    "Your DHL shipment is on hold. Pay customs fee using this link today.",
    "Important: update your account details to continue using our services.",
]
LEGIT = [
    "Hi team, the meeting is moved to 3pm tomorrow in conference room B.",
    "Thanks for your order. Your receipt is attached for your records.",
    "Can you review the draft report and send me your comments by Friday?",
    "Happy birthday! Hope you have a wonderful day with your family.",
    "Reminder: the library will be closed on Monday for the public holiday.",
    "Here are the notes from today's lecture on data structures.",
    "Your monthly newsletter: new recipes and gardening tips for spring.",
    "Let's grab lunch next week. Does Wednesday work for you?",
    "The project deadline has been extended to the end of the month.",
    "Please find attached the agenda for next week's board meeting.",
    "Your flight booking is confirmed. Check-in opens 24 hours before departure.",
    "We have updated our privacy policy. You can read it on our website anytime.",
    "Great job on the presentation today, the client was impressed.",
    "The school bus schedule for next semester is now available.",
    "Could you send me the photos from the weekend trip?",
    "Your subscription has been renewed successfully. No action is required.",
    "Team building event this Friday, pizza will be provided.",
    "I've pushed the latest code changes, please pull and test.",
    "Doctor's appointment reminder for Tuesday at 10am.",
    "Thanks for attending our webinar. Slides are available in the course portal.",
    "The quarterly sales numbers look good, let's discuss in our next sync.",
    "Mom says dinner is at 7, don't be late.",
    "Welcome to the club! Our first meetup is on Saturday at the park.",
    "Your package was delivered to the front door this afternoon.",
    "Please remember to submit your timesheet before the end of the week.",
    "The weather looks nice this weekend, want to go hiking?",
    "Attached is the invoice for consulting services as discussed last month.",
    "Our office will be closed for maintenance on Sunday morning.",
    "I finished reading the book you recommended, it was excellent.",
    "New features released in version 2.1, see the changelog for details.",
]


def train():
    texts = PHISHING + LEGIT
    labels = [1] * len(PHISHING) + [0] * len(LEGIT)
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000, C=5.0)),
    ])
    pipeline.fit(X_train, y_train)
    print("Evaluation on held-out test set:")
    print(classification_report(y_test, pipeline.predict(X_test), zero_division=0))

    # Retrain on all data for the final model
    pipeline.fit(texts, labels)
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
