// Initialize service account credentials variable
let serviceAccountCreds;

// Initialize service account from injected config
async function initializeServiceAccount() {
    try {
        if (!window.SERVICE_ACCOUNT_KEY) {
            throw new Error('Service account key not found');
        }
        serviceAccountCreds = JSON.parse(window.SERVICE_ACCOUNT_KEY);
        validateServiceAccountCreds();
    } catch (error) {
        console.error('Failed to initialize service account:', error);
        showStatus('Failed to initialize service account credentials', 'error');
        throw error;
    }
}

// Validate service account credentials
function validateServiceAccountCreds() {
    const requiredFields = [
        'client_email',
        'private_key',
        'token_uri',
        'type'
    ];
    
    const missingFields = requiredFields.filter(field => !serviceAccountCreds[field]);
    
    if (missingFields.length > 0) {
        throw new Error(`Missing required service account fields: ${missingFields.join(', ')}`);
    }

    if (serviceAccountCreds.type !== 'service_account') {
        throw new Error('Invalid credential type. Must be "service_account"');
    }
}

// Base64URL encoding utility
function base64URLEncode(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// Get access token using JWT
async function getAccessToken() {
    try {
        const header = {
            alg: 'RS256',
            typ: 'JWT'
        };

        const now = Math.floor(Date.now() / 1000);
        const claim = {
            iss: serviceAccountCreds.client_email,
            scope: 'https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file',
            aud: serviceAccountCreds.token_uri,
            exp: now + 3600,
            iat: now
        };

        const encodedHeader = base64URLEncode(new TextEncoder().encode(JSON.stringify(header)));
        const encodedClaim = base64URLEncode(new TextEncoder().encode(JSON.stringify(claim)));
        const signatureInput = `${encodedHeader}.${encodedClaim}`;

        const privateKey = serviceAccountCreds.private_key
            .replace(/\\n/g, '\n')
            .trim();

        const importedKey = await crypto.subtle.importKey(
            'pkcs8',
            new TextEncoder().encode(privateKey),
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256'
            },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            importedKey,
            new TextEncoder().encode(signatureInput)
        );

        const encodedSignature = base64URLEncode(signature);
        const jwt = `${encodedHeader}.${encodedClaim}.${encodedSignature}`;

        const response = await fetch(serviceAccountCreds.token_uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Token error: ${errorData.error}: ${errorData.error_description}`);
        }

        const data = await response.json();
        if (!data.access_token) {
            throw new Error('No access token received');
        }

        return data.access_token;
    } catch (error) {
        console.error('Authentication error:', error);
        showStatus(`Authentication failed: ${error.message}`, 'error');
        throw error;
    }
}

// Create or get upload folder
async function createServiceAccountFolder(accessToken, folderName = 'Uploads') {
    // Check if folder exists
    const searchResponse = await fetch(
        `https://www.googleapis.com/drive/v3/files?q=name='${folderName}' and mimeType='application/vnd.google-apps.folder' and 'root' in parents and trashed=false`, {
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });
    
    const searchResult = await searchResponse.json();
    
    if (searchResult.files && searchResult.files.length > 0) {
        return searchResult.files[0].id;
    }

    // Create new folder if it doesn't exist
    const response = await fetch('https://www.googleapis.com/drive/v3/files', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: folderName,
            mimeType: 'application/vnd.google-apps.folder'
        })
    });

    const result = await response.json();
    return result.id;
}

// List files in the upload folder
async function listFiles() {
    try {
        validateServiceAccountCreds();
        
        const accessToken = await getAccessToken();
        
        if (!accessToken) {
            throw new Error('Failed to obtain access token');
        }

        const driveFiles = document.getElementById('driveFiles');
        driveFiles.innerHTML = '<div class="loading">Loading files...</div>';

        const folderId = await createServiceAccountFolder(accessToken);
        
        const response = await fetch(
            `https://www.googleapis.com/drive/v3/files?q='${folderId}' in parents and trashed=false&pageSize=1000&fields=files(id,name,mimeType,size,modifiedTime)`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Drive API error: ${errorData.error?.message || response.statusText}`);
        }

        const result = await response.json();
        
        if (result.files && result.files.length > 0) {
            driveFiles.innerHTML = result.files.map(file => `
                <div class="drive-file">
                    <div>
                        <strong>${file.name}</strong>
                        <br>
                        <small>Modified: ${new Date(file.modifiedTime).toLocaleString()}</small>
                        ${file.size ? `<br><small>Size: ${formatFileSize(file.size)}</small>` : ''}
                    </div>
                    <a href="https://drive.google.com/file/d/${file.id}/view" target="_blank">View</a>
                </div>
            `).join('');
        } else {
            driveFiles.innerHTML = '<p>No files found</p>';
        }
    } catch (error) {
        console.error('Error listing files:', error);
        showStatus(`Error listing files: ${error.message}`, 'error');
        document.getElementById('driveFiles').innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// Upload files to Drive
async function uploadFiles() {
    const fileInput = document.getElementById('fileInput');
    const uploadButton = document.getElementById('uploadButton');
    const files = fileInput.files;

    if (files.length === 0) {
        showStatus('Please select at least one file', 'error');
        return;
    }

    uploadButton.disabled = true;
    
    try {
        const accessToken = await getAccessToken();
        const folderId = await createServiceAccountFolder(accessToken);

        for (let file of files) {
            const fileItem = createFileListItem(file.name);
            
            try {
                // Create file metadata
                const metadata = {
                    name: file.name,
                    parents: [folderId]
                };

                // First, create the file metadata
                const createResponse = await fetch('https://www.googleapis.com/drive/v3/files', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(metadata)
                });

                if (!createResponse.ok) {
                    throw new Error(`Failed to create file metadata: ${createResponse.statusText}`);
                }

                const fileMetadata = await createResponse.json();

                // Then upload the file content
                const uploadResponse = await fetch(
                    `https://www.googleapis.com/upload/drive/v3/files/${fileMetadata.id}?uploadType=media`, {
                    method: 'PATCH',
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'Content-Type': file.type || 'application/octet-stream'
                    },
                    body: file
                });

                if (!uploadResponse.ok) {
                    throw new Error(`Failed to upload file content: ${uploadResponse.statusText}`);
                }

                const result = await uploadResponse.json();
                updateFileListItem(fileItem, true, result.id);
                showStatus(`Successfully uploaded: ${file.name}`, 'success');
                
            } catch (error) {
                updateFileListItem(fileItem, false);
                showStatus(`Error uploading ${file.name}: ${error.message}`, 'error');
                console.error(`Error uploading ${file.name}:`, error);
            }
        }
        
        // Refresh the files list after uploads
        await listFiles();
        
    } catch (error) {
        showStatus(`Error: ${error.message}`, 'error');
        console.error('Upload error:', error);
    } finally {
        uploadButton.disabled = false;
    }
}

// Create file list item with progress bar
function createFileListItem(fileName) {
    const fileList = document.getElementById('fileList');
    const fileItem = document.createElement('div');
    fileItem.className = 'file-item';
    fileItem.innerHTML = `
        <div>
            <div>${fileName}</div>
            <div class="progress-bar">
                <div class="progress"></div>
            </div>
        </div>
    `;
    fileList.appendChild(fileItem);
    return fileItem;
}

// Update file list item status
function updateFileListItem(fileItem, success, fileId = null) {
    const progressBar = fileItem.querySelector('.progress');
    progressBar.style.width = '100%';
    progressBar.style.backgroundColor = success ? '#4CAF50' : '#f44336';
    
    if (success && fileId) {
        const link = document.createElement('a');
        link.href = `https://drive.google.com/file/d/${fileId}/view`;
        link.target = '_blank';
        link.textContent = 'View';
        fileItem.appendChild(link);
    }
}

// Show status message
function showStatus(message, type) {
    const statusDiv = document.getElementById('uploadStatus');
    statusDiv.textContent = message;
    statusDiv.style.display = 'block';
    statusDiv.className = type;

    // Auto-hide success messages after 5 seconds
    if (type === 'success') {
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 5000);
    }
}

// Format file size for display
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Initialize the application
document.addEventListener('DOMContentLoaded', async () => {
    try {
        await initializeServiceAccount();
        listFiles();
    } catch (error) {
        console.error('Initialization error:', error);
        showStatus(`Initialization failed: ${error.message}`, 'error');
    }
});
