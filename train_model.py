import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

print("=" * 50)
print("  CloudMalScan ML Model Trainer")
print("=" * 50)

# ── STEP 1: Load Dataset ───────────────────────────
print("\n[1/5] Loading dataset...")
try:
    df = pd.read_csv("datasets/cmd_2024.csv")
    print(f"      ✅ Loaded {len(df)} samples")
except FileNotFoundError:
    print("      ❌ Dataset not found!")
    exit()

# ── STEP 2: Prepare Data ───────────────────────────
print("\n[2/5] Preparing data...")

# Label column
label_col = "family"
X = df.drop(columns=[label_col])
y = df[label_col]

# Keep only numeric columns
X = X.select_dtypes(include=[np.number])
X = X.fillna(0)

print(f"      ✅ Features : {X.shape[1]} columns")
print(f"      ✅ Samples  : {X.shape[0]} rows")
print(f"      ✅ Classes  : {y.unique()}")

# ── STEP 3: Encode Labels ─────────────────────────
print("\n[3/5] Encoding labels...")
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"      ✅ {len(le.classes_)} classes encoded")

# ── STEP 4: Train Model ───────────────────────────
print("\n[4/5] Training Random Forest model...")
print("      Please wait 1-2 minutes...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
)
clf.fit(X_train, y_train)
print("      ✅ Training done!")

# ── STEP 5: Evaluate ──────────────────────────────
print("\n[5/5] Evaluating model...")
y_pred   = clf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n{'=' * 50}")
print(f"  ACCURACY : {accuracy * 100:.2f}%")
print(f"{'=' * 50}")
print("\nDetailed Classification Report:")
print(classification_report(
    y_test, y_pred,
    target_names=le.classes_,
    zero_division=0
))

# ── SAVE MODEL ────────────────────────────────────
print("Saving model files...")
os.makedirs("app/models", exist_ok=True)

joblib.dump(clf,            "app/models/malware_classifier.pkl")
joblib.dump(le,             "app/models/label_encoder.pkl")
joblib.dump(list(X.columns),"app/models/feature_names.pkl")

print("\n✅ malware_classifier.pkl saved")
print("✅ label_encoder.pkl saved")
print("✅ feature_names.pkl saved")
print("\n🎉 Model is ready to use in CloudMalScan!")
