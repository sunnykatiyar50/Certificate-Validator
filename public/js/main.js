document.addEventListener('DOMContentLoaded', function() {
    const certificateForm = document.getElementById('certificate-form');
    const resultContainer = document.getElementById('result-container');
    const validationResults = document.getElementById('validation-results');
    
    certificateForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const fileInput = document.getElementById('certificate');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a certificate file');
            return;
        }
        
        const formData = new FormData();
        formData.append('certificate', file);
        
        // Show loading state
        validationResults.innerHTML = '<p>Validating certificate...</p>';
        resultContainer.style.display = 'block';
        
        // Send the certificate to the server for validation
        fetch('/validate-certificate', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Display validation results
            let resultsHTML = '<h3>Certificate Details:</h3>';
            
            if (data.valid) {
                resultsHTML += '<p class="valid">✓ Certificate is valid</p>';
            } else {
                resultsHTML += '<p class="invalid">✗ Certificate is invalid</p>';
                if (data.error) {
                    resultsHTML += `<p class="invalid">Error: ${data.error}</p>`;
                }
            }
            
            if (data.details) {
                resultsHTML += '<ul>';
                for (const [key, value] of Object.entries(data.details)) {
                    resultsHTML += `<li><strong>${key}:</strong> ${value}</li>`;
                }
                resultsHTML += '</ul>';
            }
            
            validationResults.innerHTML = resultsHTML;
        })
        .catch(error => {
            console.error('Error:', error);
            validationResults.innerHTML = `<p class="invalid">Error: ${error.message}</p>`;
        });
    });
});