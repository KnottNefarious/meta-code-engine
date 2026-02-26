// Update to handle API response properly

async function displayAnalysisResults(apiResponse) {
    const resultsContainer = document.getElementById('results');

    // Clear existing results
    resultsContainer.innerHTML = '';

    try {
        if (!apiResponse || !apiResponse.issues) {
            throw new Error('Invalid API response');
        }

        const issues = apiResponse.issues;
        const status = apiResponse.status;

        // Display status
        const statusElement = document.createElement('div');
        statusElement.innerHTML = `<h2>Status: ${status}</h2>`;
        resultsContainer.appendChild(statusElement);

        // Display issues
        issues.forEach(issue => {
            const issueElement = document.createElement('div');
            issueElement.innerHTML = `<p>Issue: ${issue.description}</p>`;
            resultsContainer.appendChild(issueElement);
        });
    } catch (error) {
        // Handle errors
        const errorElement = document.createElement('div');
        errorElement.innerHTML = `<p>Error: ${error.message}</p>`;
        resultsContainer.appendChild(errorElement);
    }
}