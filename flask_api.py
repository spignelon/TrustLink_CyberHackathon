from flask import Flask, request, jsonify
from transformers import pipeline

app = Flask(__name__)

# Load the text classification pipeline
pipe = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs", return_all_scores=True)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Extract the URL from the JSON data
        url = data['url']

        # Make prediction using the pipeline
        result = pipe(url)

        # Return the prediction as JSON
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
