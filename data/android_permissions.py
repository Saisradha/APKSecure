import pandas as pd

# Load dataset
df = pd.read_csv("C:\Users\saisr\OneDrive\Desktop\APKSecure\data\android_permissions.csv")

# Check structure
print(df.head())
print(f"Total apps: {len(df)}")
print(f"Malware count: {df['CLASS'].sum()}")  # CLASS: 0=Benign, 1=Malware
print(f"Permission columns: {len(df.columns) - 2}")  # Minus NAME and CLASS

# Check permission distribution
top_perms = df.iloc[:, 1:-1].sum().sort_values(ascending=False).head(10)
print("\nTop 10 most used permissions:")
print(top_perms)
