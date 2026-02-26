from flask import Flask, render_template  
from DissonanceDetector import DissonanceDetector  

app = Flask(__name__)  

@app.route('/')  
def index():  
    detector = DissonanceDetector()  
    # Example use of the detector, update with your logic  
    return render_template('index.html')  

if __name__ == '__main__':  
    app.run(debug=True)