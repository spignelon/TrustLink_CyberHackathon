# import streamlit as st
# from transformers import pipeline

# pipe = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs",return_all_scores=True)

# pipe("google.com")

import streamlit as st
from transformers import pipeline
import plotly.graph_objects as go
pipe = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs", top_k=None)

# result = pipe("google.com")

# pipe("google.com")
dick={'Benign': 1,'Defacement': 2, 'Malware': 3,'Phishing':4}


def analyze_url(url):
    result = pipe(url)
    # label = result[0][0]['label']
    # score = result[0][0]['score']
    # print(result)
    # return f"The URL is classified as {label} with a confidence score of {score:.2%}"
    # label=[]
    # score=[]
    # for i in range(0,4):
    #     l=result[0][i]['label']
    #     s = result[0][i]['score']
    #     label.append(l)
    #     score.append(s)
    #     # print(label,score)
    dick['Benign']=score = result[0][0]['score']
    dick['Defacement']=score = result[0][1]['score']
    dick['Malware']=score = result[0][2]['score']
    dick['Phishing']=score = result[0][3]['score']
    for label, score in dick.items():
        print(f"{label}: {score}")
        
    sorted_data = dict(sorted(dick.items(), key=lambda item: item[1], reverse=False))
    return sorted_data

print(analyze_url("google.com"))

st.title("URL Classifier")
st.write("Enter a URL to classify it.")

# Input field for URL
url = st.text_input("Enter URL", "https://example.com")

# Button to analyze URL
if st.button("Analyze"):
    # label,score = analyze_url(url)
    label=[]
    score=[]
    for l, s in analyze_url(url).items():
        label.append(l)
        score.append(s)
    # st.write(analyze_url(url))
    # st.write(label,score)
    
    for i in range(0,4,1):
        st.write(label[i]," : ", round(score[i] * 100, 2), "%")
        
    fig = go.Figure(go.Bar(y=label, x=score, orientation='h'))
    fig.update_layout(title="Analysis Result", xaxis_title="Score", yaxis_title="Label")
    
    # Display the chart using Streamlit's Plotly support
    st.plotly_chart(fig)





