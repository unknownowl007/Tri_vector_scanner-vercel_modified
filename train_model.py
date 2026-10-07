import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

from features import extract_features

# Load the training and test datasets.
print("Loading cleaned data...")
df_train = pd.read_csv("datasets/cleaned_train.csv")
df_test = pd.read_csv("datasets/cleaned_test.csv")

# Extract URL features for both datasets.
X_train = df_train["url"].apply(extract_features).tolist()
y_train = df_train["label"]
X_test = df_test["url"].apply(extract_features).tolist()
y_test = df_test["label"]

# Train the Random Forest classifier.
print("Training Tuned Random Forest Engine...")
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=30,
    min_samples_split=2,
    class_weight="balanced",
    random_state=42,
)
model.fit(X_train, y_train)

# Evaluate the classifier on the test dataset.
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"\n==============================")
print(f"ACCURACY: {accuracy * 100:.2f}%")
print(f"==============================")

# Save the trained classifier.
joblib.dump(model, "model/phishing_model.pkl")
print("Model saved as model/phishing_model.pkl")
