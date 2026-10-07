from sklearn.feature_extraction.text import TfidfVectorizer


def analyze_job_text(descriptions):
    """
    Convert job descriptions into TF-IDF features.
    """

    vectorizer = TfidfVectorizer(
        stop_words="english",
        max_features=50
    )

    tfidf_matrix = vectorizer.fit_transform(descriptions)

    feature_names = vectorizer.get_feature_names_out()

    return tfidf_matrix, feature_names


def get_top_keywords(tfidf_matrix, feature_names, top_n=5):
    """
    Get the most important keywords for each job posting.
    """

    top_keywords = []

    for row in tfidf_matrix:

        scores = row.toarray().flatten()

        top_indices = scores.argsort()[-top_n:][::-1]

        keywords = [
            feature_names[index]
            for index in top_indices
            if scores[index] > 0
        ]

        top_keywords.append(keywords)

    return top_keywords