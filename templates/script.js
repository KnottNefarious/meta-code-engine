// script.js

// Function to handle form submission
function handleFormSubmit(event) {
    event.preventDefault(); // Prevent the default form submission

    // Get the code from the form input
    const code = document.getElementById('codeInput').value;

    // Send the code to the /api/analyze endpoint
    fetch('/api/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code })
    })
    .then(response => response.json())
    .then(data => {
        // Display the analysis results
        const resultContainer = document.getElementById('results');
        if (data.success) {
            resultContainer.innerHTML = '<h3>Analysis Results</h3>' + JSON.stringify(data.result);
        } else {
            resultContainer.innerHTML = '<h3>Error</h3>' + data.message;
        }
    })
    .catch(error => {
        // Handle any errors
        const resultContainer = document.getElementById('results');
        resultContainer.innerHTML = '<h3>Error</h3>' + error.message;
    });
}

// Add the event listener to the form
document.getElementById('myForm').addEventListener('submit', handleFormSubmit);