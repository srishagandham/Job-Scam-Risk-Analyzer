import pandas as pd
from scam_detector import detect_scam_indicators
from nlp_analyzer import analyze_job_text, get_top_keywords


# Load job postings
df = pd.read_csv("data/job_postings.csv")
# NLP analysis
tfidf_matrix, feature_names = analyze_job_text(
    df["description"].tolist()
)
top_keywords = get_top_keywords(
    tfidf_matrix,
    feature_names,
    top_n=5
)


print("NLP analysis completed!")
print(f"Number of documents: {tfidf_matrix.shape[0]}")
print(f"Number of NLP features: {tfidf_matrix.shape[1]}")
print()

print("Job postings loaded successfully!")
print()


# Analyze each job posting
for index, row in df.iterrows():

    score, risk_level, indicators = detect_scam_indicators(
        row["description"],
        row["salary"],
        row["email"],
        row["company"],
        top_keywords[index]
    )

    print("=" * 60)
    print(f"Job ID: {row['job_id']}")
    print(f"Title: {row['title']}")
    print(f"Company: {row['company']}")
    print(f"Risk Score: {score}/100")
    print(f"Risk Level: {risk_level}")
    print(f"NLP Keywords: {', '.join(top_keywords[index])}")

    if indicators:

        print("Detected Indicators:")

        for indicator in indicators:
            print(f"- {indicator}")
    else:
        print("No major scam indicators detected.")

print("=" * 60)