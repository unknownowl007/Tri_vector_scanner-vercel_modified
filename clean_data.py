import pandas as pd

"""Clean the training and test CSV files and convert labels to numeric values."""

# Clean the training dataset.
df_train = pd.read_csv("datasets/Training.csv")
df_train = df_train.dropna()

# Convert the source status values to the numeric labels used by the model.
df_train["label"] = df_train["status"].map({"phishing": 1, "legitimate": 0})
df_train = df_train.drop(columns=["status"])

df_train.to_csv("datasets/cleaned_train.csv", index=False)
print("Training data cleaned!")


# Clean the test dataset.
df_test = pd.read_csv("datasets/Testing.csv")
df_test = df_test.dropna()

df_test["label"] = df_test["status"].map({"phishing": 1, "legitimate": 0})
df_test = df_test.drop(columns=["status"])

df_test.to_csv("datasets/cleaned_test.csv", index=False)
print("Testing data cleaned!")
