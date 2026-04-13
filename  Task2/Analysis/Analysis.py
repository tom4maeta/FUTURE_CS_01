# analysis.py
# Full Phishing Email Analysis Script - Plots saved as PNG

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

# ==============================
# 1. Load the dataset
# ==============================
file_path = "email_phishing_data.csv"  # Change path if needed
data = pd.read_csv(file_path)

print("Dataset Loaded Successfully\n")
print("First 5 Rows of the Dataset:")
print(data.head())
print("\nDataset Info:")
print(data.info())
print("\nDataset Shape:", data.shape)

# ==============================
# 2. Basic statistics
# ==============================
print("\n--- Label Distribution ---")
print(data['label'].value_counts())
print("\nPercentage Distribution:")
print(data['label'].value_counts(normalize=True)*100)

print("\n--- Descriptive Statistics ---")
print(data.describe())

# ==============================
# 3. Group by label and analyze features
# ==============================
print("\n--- Average Feature Values by Label ---")
label_group = data.groupby('label').mean()
print(label_group)

# ==============================
# 4. Correlation Analysis
# ==============================
plt.figure(figsize=(10,8))
sns.heatmap(data.corr(), annot=True, cmap="coolwarm")
plt.title("Feature Correlation Heatmap")
plt.savefig("correlation_heatmap.png")
plt.close()

# ==============================
# 5. Visualization
# ==============================

# Distribution of phishing vs legitimate emails
plt.figure(figsize=(6,4))
data['label'].value_counts().plot(kind='bar', color=['green','red'])
plt.title("Legitimate vs Phishing Emails")
plt.xlabel("Label (0=Legitimate, 1=Phishing)")
plt.ylabel("Count")
plt.savefig("label_distribution.png")
plt.close()

# Boxplot: Number of links vs label
plt.figure(figsize=(6,4))
sns.boxplot(x='label', y='num_links', data=data)
plt.title("Number of Links in Emails")
plt.savefig("num_links_boxplot.png")
plt.close()

# Boxplot: Urgent keywords vs label
plt.figure(figsize=(6,4))
sns.boxplot(x='label', y='num_urgent_keywords', data=data)
plt.title("Urgent Keywords in Emails")
plt.savefig("urgent_keywords_boxplot.png")
plt.close()

# Boxplot: Spelling errors vs label
plt.figure(figsize=(6,4))
sns.boxplot(x='label', y='num_spelling_errors', data=data)
plt.title("Spelling Errors in Emails")
plt.savefig("spelling_errors_boxplot.png")
plt.close()

# ==============================
# 6. Rule-based Phishing Detection
# ==============================
# Simple rules:
#  - More than 2 links
#  - At least 1 urgent keyword
#  - More than 0 spelling errors
data['predicted_phishing'] = (
    (data['num_links'] > 2) |
    (data['num_urgent_keywords'] > 0) |
    (data['num_spelling_errors'] > 0)
).astype(int)

# Accuracy check
accuracy = (data['label'] == data['predicted_phishing']).mean()
print(f"\nRule-based Detection Accuracy: {accuracy*100:.2f}%")

# Confusion matrix
cm = confusion_matrix(data['label'], data['predicted_phishing'])
print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(data['label'], data['predicted_phishing']))

# Save confusion matrix plot
plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Legit','Phish'], yticklabels=['Legit','Phish'])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.savefig("confusion_matrix.png")
plt.close()

# ==============================
# 7. Top Phishing Indicators
# ==============================
phishing_avg = data[data['label']==1].mean()
print("\n--- Average Features in Phishing Emails ---")
print(phishing_avg)

# ==============================
# 8. Export flagged phishing emails
# ==============================
flagged_emails = data[data['predicted_phishing']==1]
flagged_emails.to_csv("flagged_phishing_emails.csv", index=False)
print("\nFlagged phishing emails exported to 'flagged_phishing_emails.csv'")

# ==============================
# 9. Summary for cybersecurity report
# ==============================
print("\n--- Summary ---")
print("Total Emails:", len(data))
print("Legitimate Emails:", len(data[data['label']==0]))
print("Actual Phishing Emails:", len(data[data['label']==1]))
print("Detected Phishing Emails:", len(flagged_emails))
print("Rule-based detection identifies suspicious emails based on links, urgent keywords, and spelling errors.")

print("\nAnalysis Completed Successfully!")