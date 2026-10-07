FEATURE_LABELS = (
    "URL length", "Hostname length", "Path length", "Query length", "Dots",
    "Hyphens", "At signs", "Question marks", "Underscores or encoded characters",
    "Path slashes", "Equals signs", "Ampersands", "Colons", "Subdomain count",
    "HTTPS scheme", "IP-address host", "Nonstandard port", "Embedded user info",
    "URL digit ratio", "Hostname digit ratio", "Suspicious words", "Brand text in hostname",
    "Known URL shortener", "Punycode hostname", "Path depth", "Query parameter count",
    "URL fragment", "Encoded-character count", "Hostname character entropy", "URL character entropy",
    "Longest digit sequence", "Double slash in path", "Suspicious top-level domain",
    "Digits in hostname", "Risky file extension",
)


def explain_random_forest(model, features, limit=5):
    if not hasattr(model, "estimators_") or not hasattr(model, "classes_"):
        return {"method": "feature_snapshot", "signals": []}
    classes = list(model.classes_)
    if 1 not in classes:
        return {"method": "feature_snapshot", "signals": []}
    phishing_index = classes.index(1)
    vector = features[0]
    contributions = [0.0] * len(vector)
    baseline = 0.0

    for estimator in model.estimators_:
        tree = estimator.tree_
        node = 0
        node_probability = tree.value[node][0][phishing_index] / sum(tree.value[node][0])
        baseline += node_probability / len(model.estimators_)
        while tree.children_left[node] != tree.children_right[node]:
            feature = tree.feature[node]
            child = tree.children_left[node] if vector[feature] <= tree.threshold[node] else tree.children_right[node]
            child_values = tree.value[child][0]
            child_probability = child_values[phishing_index] / sum(child_values)
            contributions[feature] += (child_probability - node_probability) / len(model.estimators_)
            node, node_probability = child, child_probability

    signals = []
    for index, contribution in enumerate(contributions):
        if index >= len(FEATURE_LABELS) or abs(contribution) < 0.005:
            continue
        signals.append({
            "feature": FEATURE_LABELS[index],
            "value": round(float(vector[index]), 3),
            "effect": "increased" if contribution > 0 else "decreased",
            "impact": round(abs(contribution) * 100, 2),
        })
    signals.sort(key=lambda item: item["impact"], reverse=True)
    return {
        "method": "random_forest_path_contribution",
        "baseline_phishing_probability": round(baseline * 100, 2),
        "signals": signals[:limit],
        "note": "Signals show how this model's tree paths shifted its phishing score; they are not proof of intent or safety.",
    }
