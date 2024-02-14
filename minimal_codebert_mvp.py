import gradio as gr
from transformers import pipeline

# Load the text classification pipeline
pipe = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs", return_all_scores=True)

# Function to perform analysis on the provided URL
def analyze_url(url):
    result = pipe(url)
    label = result[0][0]['label']
    score = result[0][0]['score']
    return f"The URL is classified as {label} with a confidence score of {score:.2%}", result

# Gradio Interface
iface = gr.Interface(
    fn=analyze_url,
    inputs=gr.Textbox(label="Enter URL", placeholder="e.g., https://example.com"),
    outputs=[gr.Textbox("Result", label="Analysis Result"), gr.Label(label="Categories")],
    live=False, 
    title="Malicious URL Detector",
    description="Enter a URL to check if it's malicious.",
    theme='derekzen/stardust',
)

# with gr.Row():
    # gr.Label(value={"Phishing": result[0][0]['label'], "Benign": result[0][1]['label'], "Defacement": result[0][2]['label'], "malware": result[][3]['label']})

iface.launch(share=True)
