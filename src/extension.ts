import * as vscode from 'vscode';
import polka = require('polka');
import * as crypto from 'crypto';

interface TimeEntry {
    path: string;
    project ? : string | undefined;
    startTime: number;
    endTime ? : number;
    id ? : string;
    created_at ? : number;
}

let statusBarItem: vscode.StatusBarItem;
let currentTimeEntry: TimeEntry | undefined;
let updateInterval: ReturnType < typeof setInterval > | undefined;
statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
);


interface AuthResponse {
    access_token: string;
    token_type: string;
    expires_in ? : number;
}

interface ErrorResponse {
    error: string;
    message ? : string;
}

export class AuthenticationProvider {
    private static readonly SESSION_KEY = 'laravel-auth-session';
    private static readonly AUTH_TYPE = 'laravel';
    private baseUrl: string;
    private token: string | undefined;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext, baseUrl: string = 'http://localhost:8000') {
        this.context = context;
        this.baseUrl = baseUrl;
    }

    async authenticate(): Promise < string > {
        const state = crypto.randomBytes(16).toString('hex');
        const server = polka();

        return new Promise((resolve, reject) => {
            server.get('/callback', async (req: any, res: any) => {
                try {
                    if (req.query.state !== state) {
                        throw new Error('Invalid state parameter');
                    }

                    const response = await fetch(`${this.baseUrl}/vscode/callback`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        },
                        body: JSON.stringify({
                            code: req.query.code
                        })
                    });

                    console.log('Response status:', response.status);
                    console.log('Response headers:', [...response.headers.entries()]);

                    // If response is not ok, handle the error
                    if (!response.ok) {
                        const errorText = await response.text();
                        console.error('Error response:', errorText);
                        throw new Error(`HTTP error! status: ${response.status}\n${errorText}`);
                    }

                    // Try to parse JSON response with type checking
                    const jsonData = await response.json();

                    // Type guard function to check if response is AuthResponse
                    const isAuthResponse = (data: unknown): data is AuthResponse => {
                        return (
                            typeof data === 'object' &&
                            data !== null &&
                            'access_token' in data &&
                            typeof(data as AuthResponse).access_token === 'string'
                        );
                    };

                    if (!isAuthResponse(jsonData)) {
                        console.error('Invalid response structure:', jsonData);
                        throw new Error('Invalid response format from server');
                    }

                    this.token = jsonData.access_token;
                    await this.storeToken(this.token);

                    server.server?.close();
                    vscode.window.showInformationMessage('Successfully authenticated with Laravel!');

                    resolve(this.token);
                } catch (err) {
                    // Proper error handling with type checking
                    const error = err as Error;
                    console.error('Authentication error:', error);
                    vscode.window.showErrorMessage(`Authentication failed: ${error.message}`);
                    reject(error);
                }

                res.end(`<h1>Authentication process completed. You can close this window.</h1>`);
            });

            server.listen(0, () => {
                const port = (server.server?.address() as any).port;
                const authUrl = `${this.baseUrl}/vscode/authorize?` +
                    `state=${state}&redirect_uri=http://localhost:${port}/callback`;

                console.log('Authorization URL:', authUrl);
                vscode.env.openExternal(vscode.Uri.parse(authUrl));
            });
        });
    }

    async isAuthenticated(): Promise < boolean > {
        try {
            const token = await this.getStoredToken();
            if (!token) {
                return false;
            }

            // Verify token validity by making a request to Laravel
            const response = await fetch(`${this.baseUrl}/api/user`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });

            return response.ok;
        } catch (error) {
            return false;
        }
    }

    // Logout method
    async logout(): Promise < void > {
        try {
            const token = await this.getStoredToken();
            if (token) {
                // Call Laravel logout endpoint
                await fetch(`${this.baseUrl}/api/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json'
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            // Clear the stored token
            await this.context.secrets.delete(AuthenticationProvider.SESSION_KEY);
            this.token = undefined;
        }
    }



    private async storeToken(token: string): Promise < void > {
        await this.context.secrets.store(AuthenticationProvider.SESSION_KEY, token);
    }

    async getStoredToken(): Promise < string | undefined > {
        return await this.context.secrets.get(AuthenticationProvider.SESSION_KEY);
    }

    async makeAuthenticatedRequest < T > (endpoint: string, options: RequestInit = {}): Promise < T > {
        const token = await this.getStoredToken();
        if (!token) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}\n${errorText}`);
        }

        return await response.json() as T;
    }
}



export class OfflineSyncManager {
    private context: vscode.ExtensionContext;
    private static readonly PENDING_ENTRIES_KEY = 'pending_time_entries';
    private baseUrl: string;

    constructor(context: vscode.ExtensionContext, baseUrl: string = 'http://127.0.0.1:8000') {
        this.context = context;
        this.baseUrl = baseUrl;
    }

    // Save time entry with offline fallback
    async saveTimeEntry(timeEntry: TimeEntry, token: string | undefined): Promise < void > {
        if (!token) {
            token = '';
        }



        try {
            if (!timeEntry.path) {
                throw new Error('Something went wrong');
            }

            const response = await fetch(`${this.baseUrl}/api/wahda`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(timeEntry)
            });

            if (!response.ok) {
                console.log('not okay');

                throw new Error(`HTTP error! status: ${response.status}`);
            }

            await response.json();

        } catch (error) {
            console.log('Saving offline due to error:', error);
            // Add timestamp when saving offline
            timeEntry.created_at = new Date().getTime();
            await this.saveOffline(timeEntry);
            console.log(timeEntry);
            vscode.window.showInformationMessage('Time entry saved offline. Will sync when connection is restored.');
        }
    }

    // Save entry to offline storage
    private async saveOffline(timeEntry: TimeEntry): Promise < void > {
        console.log('saving offline');
        const pendingEntries = await this.getPendingEntries();

        // Add unique ID to offline entries for tracking
        const offlineEntry = {
            ...timeEntry,
            id: `offline_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        };

        pendingEntries.push(offlineEntry);
        await this.context.globalState.update(OfflineSyncManager.PENDING_ENTRIES_KEY, pendingEntries);
    }

    // Get all pending offline entries
    private async getPendingEntries(): Promise < TimeEntry[] > {
        return this.context.globalState.get < TimeEntry[] > (OfflineSyncManager.PENDING_ENTRIES_KEY, []);
    }

    // Try to sync on extension activation
    async syncOnActivation(token: string | undefined): Promise < void > {
        const pendingEntries = await this.getPendingEntries();

        if (pendingEntries.length === 0) {
            return;
        }

        try {
            // Try to sync all entries at once
            const response = await fetch(`${this.baseUrl}/barcha`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    entries: pendingEntries
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }



            // If sync was successful, clear the offline entries
            await this.clearPendingEntries();
            console.log('success saving the pending entries and its now 0', pendingEntries);

            console.log('Successfully synced offline entries');
            vscode.window.showInformationMessage(`Successfully synced ${pendingEntries.length} offline entries`);

        } catch (error) {
            console.error('Failed to sync offline entries:', error);
            // Do nothing on failure - keep the entries for next attempt
        }
    }

    // Clear all pending entries after successful sync
    private async clearPendingEntries(): Promise < void > {
        await this.context.globalState.update(OfflineSyncManager.PENDING_ENTRIES_KEY, []);
    }
}


let authProvider: AuthenticationProvider;

let syncManager: OfflineSyncManager;

let lastActiveFile: string | undefined;
let debounceTimer: NodeJS.Timeout | undefined;
let isTracking: boolean = false;
let activeFile: string | undefined;
let lastActivityTime: number = Date.now();
let activityTimer: NodeJS.Timeout | undefined;




export async function activate(context: vscode.ExtensionContext) {

    try{
        authProvider = new AuthenticationProvider(context);
        syncManager = new OfflineSyncManager(context);
    
        authProvider.getStoredToken().then(token => {
            syncManager.syncOnActivation(token).catch(error => {
                console.error('Error during activation sync:', error);
            });
        });
    
        context.subscriptions.push(
            vscode.commands.registerCommand('time-tracker.authenticate', async () => {
                try {
                    const isAlreadyAuthenticated = await authProvider.isAuthenticated();
                    if (isAlreadyAuthenticated) {
                        const choice = await vscode.window.showInformationMessage(
                            'You are already authenticated. Would you like to reauthenticate?',
                            'Yes', 'No'
                        );
                        if (choice !== 'Yes') {
                            return;
                        }
                    }
    
                    await authProvider.authenticate();
                    vscode.window.showInformationMessage('Authentication successful!');
                } catch (error) {
                    vscode.window.showErrorMessage('Authentication failed: ' + error);
                }
            })
        );
    
        // Register logout command
        context.subscriptions.push(
            vscode.commands.registerCommand('time-tracker.logout', async () => {
                try {
                    await authProvider.logout();
                    vscode.window.showInformationMessage('Logged out successfully!');
                } catch (error) {
                    vscode.window.showErrorMessage('Logout failed: ' + error);
                }
            })
        );
    
    
    
    
        console.log('Time tracking extension activated');

        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor?.document.uri.scheme === 'file') {
            await handleActivity(activeEditor.document.fileName);
        }

        context.subscriptions.push(
            vscode.workspace.onDidChangeTextDocument(async (event) => {
                try {
                    if (event.document.uri.scheme === 'file') {
                        const activeEditor = vscode.window.activeTextEditor;
                        if (activeEditor?.document === event.document) {
                            await handleActivity(event.document.fileName);
                        }
                    }
                } catch (error) {
                    console.error('Error in text document change handler:', error);
                }
            }),

            vscode.window.onDidChangeActiveTextEditor(async (editor) => {
                try {
                    await stopTrackingIfNeeded();
                    if (editor?.document.uri.scheme === 'file') {
                        await handleActivity(editor.document.fileName);
                    }
                } catch (error) {
                    console.error('Error in editor change handler:', error);
                }
            }),

            vscode.window.onDidChangeTextEditorSelection(async (event) => {
                try {
                    if (event.textEditor.document.uri.scheme === 'file') {
                        await handleActivity(event.textEditor.document.fileName);
                    }
                } catch (error) {
                    console.error('Error in selection change handler:', error);
                }
            }),

            vscode.workspace.onDidCloseTextDocument(async (document) => {
                try {
                    if (activeFile === document.fileName) {
                        await stopTrackingIfNeeded();
                    }
                } catch (error) {
                    console.error('Error in document close handler:', error);
                }
            })
        );
    
    }catch(error){
        console.error('Error during activation:', error);
    }


}

export function deactivate() {
    // stopTracking();
    stopTrackingIfNeeded();
    if (activityTimer) {
        clearTimeout(activityTimer);
    }

}

async function handleActivity(fileName: string) {

    try {
        const currentTime = Date.now();

        if (isTracking && (currentTime - lastActivityTime >= 120000)) {
            await stopTrackingIfNeeded();
        }

        if (!isTracking || activeFile !== fileName) {
            await startTracking(fileName);
        }

        lastActivityTime = currentTime;

        if (activityTimer) {
            clearTimeout(activityTimer);
        }

        activityTimer = setTimeout(async () => {
            try {
                const inactiveTime = Date.now() - lastActivityTime;
                if (inactiveTime >= 60000) {
                    await stopTrackingIfNeeded();
                }
            } catch (error) {
                console.error('Error in inactivity timer:', error);
            }
        }, 60000);
    } catch (error) {
        console.error('Error in handleActivity:', error);
    }

    // const currentTime = Date.now();
    
    // // If inactive for too long, stop current tracking
    // if (isTracking && (currentTime - lastActivityTime >= 120000)) {
    //     stopTrackingIfNeeded();
    // }

    // // Start new tracking session or continue existing one
    // if (!isTracking || activeFile !== fileName) {
    //     startTracking(fileName);
    // }

    // // Update activity timestamp
    // lastActivityTime = currentTime;

    // // Reset inactivity timer
    // if (activityTimer) {
    //     clearTimeout(activityTimer);
    // }

    // activityTimer = setTimeout(() => {
    //     const inactiveTime = Date.now() - lastActivityTime;
    //     if (inactiveTime >= 60000) {
    //         stopTrackingIfNeeded();
    //     }
    // }, 60000);

    
    // console.log('hello world');
    //here ends working bloc




    // const currentTime = Date.now();
    // // If tracking a different file, stop the old one first
    // if (isTracking && activeFile && activeFile !== fileName) {
    //     stopTrackingIfNeeded();
    // }
    // // Start tracking new file
    // if (!isTracking || activeFile !== fileName) {
    //     startTracking(fileName);
    // }
    // // Update last activity time
    // lastActivityTime = currentTime;
    // // Reset inactivity timer
    // if (activityTimer) {
    //     clearTimeout(activityTimer);
    // }
    // // Set inactivity timer (1 minute)
    // activityTimer = setTimeout(() => {
    //     const inactiveTime = Date.now() - lastActivityTime;
    //     if (inactiveTime >= 60000) {
    //         stopTrackingIfNeeded();
    //     }
    // }, 60000);
}

function getWorkspaceForFile(filePath: string): string | undefined {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(filePath));
    return workspaceFolder ? workspaceFolder.name : undefined;
}

let isRunning = false;
async function stopTrackingIfNeeded() {
    try{
        if (isRunning) return; // Prevent re-entry
        isRunning = true;
    
        if (isTracking && activeFile) {
            const trackingDuration = Date.now() - lastActivityTime;
            if (currentTimeEntry    ) {
                currentTimeEntry.endTime = Date.now();
                const token = await authProvider.getStoredToken();
                if (token) { 
                    await syncManager.saveTimeEntry(currentTimeEntry, token);
                }
    
                currentTimeEntry = undefined;
    
                if (updateInterval) {
                    clearInterval(updateInterval);
                    updateInterval = undefined;
                }
    
                updateStatusBar();
            }
            isTracking = false;
            activeFile = undefined;
            isRunning = false;
            if (activityTimer) {
                clearTimeout(activityTimer);
                activityTimer = undefined;
            }
        }
    
    }catch(error){
        console.error('Error in stopTrackingIfNeeded:', error);
    }
}

async function startTracking(fileName: string) {
    try{
        activeFile = fileName;
        isTracking = true;
        isRunning = false;
        const token = await authProvider.getStoredToken();
        if (token) { 
            await syncManager.syncOnActivation(token);
        }
        currentTimeEntry = {
            path: fileName,
            startTime: Date.now(),
        };
        if (updateInterval) {
            clearInterval(updateInterval);
        }
        updateStatusBar();
        updateInterval = setInterval(updateStatusBar, 1000);
    }catch(error){
        console.error('Error in startTracking:', error);
    }
}


function updateStatusBar() {
    if (currentTimeEntry) {
        const duration = formatDuration(Date.now() - currentTimeEntry.startTime);
        statusBarItem.text = `$(clock) ${duration}`;
        statusBarItem.show();
    } else {
        statusBarItem.hide();
    }
}

function formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    return `${hours}:${(minutes % 60).toString().padStart(2, '0')}:${(seconds % 60).toString().padStart(2, '0')}`;
}