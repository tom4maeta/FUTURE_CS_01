# report.py
# Generate Cybersecurity Phishing Analysis Report

import pandas as pd

# Load the analysis outputs
data = pd.read_csv("email_phishing_data.csv")
flagged_emails = pd.read_csv("flagged_phishing_emails.csv")

# Calculate summary statistics
total_emails = len(data)
legit_emails = len(data[data['label'] == 0])
phishing_emails = len(data[data['label'] == 1])
detected_phishing = len(flagged_emails)

# Average feature values
feature_avg = data.groupby('label').mean()

# Open a text file for report
with open("phishing_analysis_report.txt", "w") as f:
    f.write("=== Phishing Email Cybersecurity Analysis Report ===\n\n")

    f.write(f"Total Emails Analyzed: {total_emails}\n")
    f.write(f"Legitimate Emails: {legit_emails}\n")
    f.write(f"Actual Phishing Emails: {phishing_emails}\n")
    f.write(f"Emails Flagged by Rule-based Detection: {detected_phishing}\n\n")

    f.write("--- Feature Analysis (Average Values) ---\n")
    f.write(feature_avg.to_string())
    f.write("\n\n")

    f.write("--- Key Observations ---\n")
    f.write("1. Phishing emails tend to have more links and urgent keywords.\n")
    f.write("2. Phishing emails have higher spelling errors.\n")
    f.write("3. Legitimate emails have fewer links and minimal urgency indicators.\n")
    f.write("4. Rule-based detection flags emails based on links, urgency, and spelling errors.\n\n")

    f.write("--- Visualizations ---\n")
    f.write("Plots saved as PNG files:\n")
    f.write("1. label_distribution.png\n")
    f.write("2. num_links_boxplot.png\n")
    f.write("3. urgent_keywords_boxplot.png\n")
    f.write("4. spelling_errors_boxplot.png\n")
    f.write("5. correlation_heatmap.png\n")
    f.write("6. confusion_matrix.png\n\n")

    f.write("--- Security Implications ---\n")
    f.write("Flagged phishing emails should be reviewed by IT Security teams.\n")
    f.write("Detection techniques can be integrated into email filters or SIEM systems.\n\n")

    f.write("Report Generated Successfully!\n")

print("Report generated as 'phishing_analysis_report.txt'")