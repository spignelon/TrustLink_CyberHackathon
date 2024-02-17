import streamlit as st
import requests
import plotly.graph_objects as go

# Function to analyze URL using the API
def analyze_url(url):
    # Define the URL of your API
    api_url = "http://127.0.0.1:5000/predict"

    # Define the input data as a dictionary
    data = {
        "url": url
    }

    # Make a POST request to the API
    response = requests.post(api_url, json=data)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Parse the JSON response
        predictions = response.json()

        # Process the predictions
        result_dict = {}
        for prediction in predictions:
            label = prediction["label"]
            if "phishing" in label.lower():
                label = "Phishing / Fraud"
            elif "malware" in label.lower():
                label = "Malware / Malicious"
            score = prediction["score"]
            result_dict[label] = score
            print(label)
        # Sort the dictionary based on scores in descending order
        sorted_data = dict(sorted(result_dict.items(), key=lambda item: item[1], reverse=False))
        
        return sorted_data
    else:
        st.error("Failed to analyze URL. Please try again.")
        return None

st.title("URL Classifier")
st.write("Enter a URL to classify it.")

# Input field for URL
url = st.text_input("Enter URL", "https://example.com")

# Button to analyze URL
if st.button("Analyze"):
    # Analyze the URL
    result = analyze_url(url)
    
    if result is not None:
        # Display the results
        for label, score in result.items():
            st.write(f"{label.title()}: {round(score * 100, 2)} %")
        print(label)
        # Plot the results
        labels = list(result.keys())
        scores = list(result.values())
        fig = go.Figure(go.Bar(y=labels, x=scores, orientation='h'))
        fig.update_layout(title="Analysis Result", xaxis_title="Score", yaxis_title="Label")
        st.plotly_chart(fig)
