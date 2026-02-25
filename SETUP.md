# Setup Instructions for Running the Flask Web Application on a Phone

Follow these steps to set up and run the Flask web application on your mobile phone:

## Prerequisites
- Ensure you have Python installed on your phone. You can use applications like Pydroid 3 for Android or Pythonista for iOS.
- Make sure to have Flask installed. If you are using Pydroid 3, you can install Flask through the built-in pip.

## Steps to Run the Application
1. **Clone the Repository**:
   - Download the repository ZIP file from GitHub or use a Git client to clone the repository to your phone.

2. **Navigate to the Project Directory**:
   - Use a file explorer or terminal in your Python environment to navigate to the directory where you cloned the repository.

3. **Install Dependencies**:
   - Make sure to install any dependencies listed in the `requirements.txt` file. You can do this by running:
     ```bash
     pip install -r requirements.txt
     ```

4. **Set the Environment Variables**:
   - Depending on your application, you might need to set environment variables. This can be done within your Python IDE or terminal.
   - For example, use the following command to set the `FLASK_ENV`:
     ```bash
     export FLASK_ENV=development
     ```

5. **Run the Application**:
   - Start your Flask app by executing:
     ```bash
     python app.py
     ```
   - Make sure to replace `app.py` with the name of your main application file.

6. **Access the Web Application**:
   - Open a web browser on your phone and navigate to `http://127.0.0.1:5000` to access the web application.
   
## Troubleshooting
- If you encounter any issues, double-check your environment setup and ensure all dependencies are installed correctly.

## Conclusion
You should now be able to run the Flask web application on your mobile device!
