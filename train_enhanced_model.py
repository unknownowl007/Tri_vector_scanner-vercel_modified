import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from enhanced_features import extract_enhanced_features


print("Loading cleaned data...")
train = pd.read_csv("datasets/cleaned_train.csv")
test = pd.read_csv("datasets/cleaned_test.csv")

X_train = [extract_enhanced_features(url) for url in train["url"]]
y_train = train["label"]
X_test = [extract_enhanced_features(url) for url in test["url"]]
y_test = test["label"]

print("Training enhanced Random Forest engine...")
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=30,
    min_samples_split=2,
    class_weight="balanced",
    random_state=42,
)
model.fit(X_train, y_train)

accuracy = accuracy_score(y_test, model.predict(X_test))
print(f"Enhanced model holdout accuracy: {accuracy * 100:.2f}%")

joblib.dump(model, "model/phishing_model_enhanced.pkl")
print("Model saved as model/phishing_model_enhanced.pkl")
