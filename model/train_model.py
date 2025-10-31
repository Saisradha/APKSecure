import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

# Load dataset
df = pd.read_csv(r"C:\Users\saisr\OneDrive\Desktop\APKSecure\data\android_permissions.csv")

# Exclude non-permission columns
exclude_cols = ['hash', 'millisecond', 'classification', 'state', 'usage_counter', 'prio']
feature_cols = [col for col in df.columns if col not in exclude_cols]

# Features and label
X = df[feature_cols].fillna(0)
X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
y = df['classification'].apply(lambda x: 1 if x == 'malware' else 0)

# Split to train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save model to disk
with open("model/apksecure_model.pkl", "wb") as f:
    pickle.dump(clf, f)

# Save the permission list for later use in backend/frontend
with open("model/permissions.pkl", "wb") as f_perm:
    pickle.dump(feature_cols, f_perm)

print("Model and permissions saved successfully.")
