import pandas as pd
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Set data directory
data_dir = './10kcsv'

# Define feature columns (simple names)
feature_cols = [
    'SPI', 'PFSI', 'TFSI', 'PPR', 'PPD'
]

# Load datasets
train_df = pd.read_csv(f"{data_dir}/overall_augmented.csv")
test_df = pd.read_csv(f"{data_dir}/overall_test_augmented.csv")

# Split features and labels, enforce column order, convert to float
X_train = train_df[feature_cols].astype(float)
y_train = train_df['label']
X_test = test_df[feature_cols].astype(float)
y_test = test_df['label']

# Define model list
models = {
    'AdaBoost': AdaBoostClassifier(n_estimators=50, random_state=42),
    'Naive Bayes': GaussianNB(),
    'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42),
    'MLP': MLPClassifier(hidden_layer_sizes=(100,), max_iter=500, random_state=42),
    'Decision Tree': DecisionTreeClassifier(max_depth=5, random_state=42)
}

# Train, predict, and evaluate each model
for name, model in models.items():
    print(f"\n==== {name} ====")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"{name} Accuracy on test data: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    print("Confusion Matrix:")
    print(cm)

