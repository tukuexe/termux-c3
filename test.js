const request = require('supertest');
const { MongoClient } = require('mongodb');
const app = require('./server.js');
require('dotenv').config();

// Test configuration
const TEST_PORT = 10001;
const TEST_MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/test_recovery';

let testServer;
let testDb;
let testUserId;
let testAccessToken;
let testDeviceId = 'test-device-1234567890';
let testFileId;

beforeAll(async () => {
    // Connect to test database
    const client = new MongoClient(TEST_MONGODB_URI);
    await client.connect();
    testDb = client.db('test_recovery');
    
    // Start test server on different port
    const { createServer } = require('http');
    testServer = createServer(app);
    testServer.listen(TEST_PORT);
    
    console.log('🧪 Test server started on port', TEST_PORT);
});

afterAll(async () => {
    if (testServer) {
        testServer.close();
    }
    
    // Cleanup test database
    if (testDb) {
        await testDb.dropDatabase();
        await testDb.client.close();
    }
    
    console.log('🧹 Test cleanup complete');
});

describe('Recovery System API - Complete Test Suite', () => {
    test('1. Health Check', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .get('/health');
        
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('healthy');
        expect(response.body.database).toBe('connected');
        console.log('✅ Health check passed');
    });
    
    test('2. User Registration', async () => {
        const userData = {
            username: 'testuser',
            password: 'testpassword123',
            device_id: testDeviceId
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/register')
            .send(userData);
        
        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Registration successful');
        expect(response.body.user_id).toBeDefined();
        
        testUserId = response.body.user_id;
        console.log('✅ User registration passed');
    });
    
    test('3. User Login', async () => {
        const loginData = {
            username: 'testuser',
            password: 'testpassword123',
            device_id: testDeviceId
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/login')
            .send(loginData);
        
        expect(response.status).toBe(200);
        expect(response.body.access_token).toBeDefined();
        expect(response.body.token_type).toBe('bearer');
        expect(response.body.expires_in).toBe(1800);
        expect(response.body.refresh_token).toBeDefined();
        
        testAccessToken = response.body.access_token;
        console.log('✅ User login passed');
    });
    
    test('4. Device Status (Protected)', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .get('/device/status')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId);
        
        expect(response.status).toBe(200);
        expect(response.body.device_id).toBe(testDeviceId);
        expect(response.body.username).toBe('testuser');
        expect(response.body.status).toBe('online');
        console.log('✅ Device status check passed');
    });
    
    test('5. Upload File Metadata', async () => {
        const fileMetadata = {
            filename: 'test-document.pdf',
            path: '/sdcard/Documents/test.pdf',
            size_bytes: 102400,
            mime_type: 'application/pdf',
            category: 'documents'
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/files/upload-metadata')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId)
            .send(fileMetadata);
        
        expect(response.status).toBe(200);
        expect(response.body.file_id).toBeDefined();
        expect(response.body.message).toBe('File metadata stored');
        expect(response.body.encryption_key).toBeDefined();
        
        testFileId = response.body.file_id;
        console.log('✅ File metadata upload passed');
    });
    
    test('6. List Files', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .get('/files/list')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId);
        
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.files)).toBe(true);
        expect(response.body.files.length).toBeGreaterThan(0);
        expect(response.body.files[0].filename).toBe('test-document.pdf');
        console.log('✅ List files passed');
    });
    
    test('7. Generate Download URL', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .get(`/files/${testFileId}/download-url`)
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId);
        
        expect(response.status).toBe(200);
        expect(response.body.download_token).toBeDefined();
        expect(response.body.expires_in).toBe(300);
        expect(response.body.filename).toBe('test-document.pdf');
        console.log('✅ Download URL generation passed');
    });
    
    test('8. Create Recovery Action', async () => {
        const actionData = {
            action_type: 'EMERGENCY_LOCK',
            parameters: {
                reason: 'Security test',
                timeout: 300
            },
            requires_confirmation: true
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/actions/create')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId)
            .send(actionData);
        
        expect(response.status).toBe(200);
        expect(response.body.action_id).toBeDefined();
        expect(response.body.requires_confirmation).toBe(true);
        expect(response.body.message).toBe('Action created successfully');
        console.log('✅ Recovery action creation passed');
    });
    
    test('9. Get Pending Actions', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .get('/actions/pending')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId);
        
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.actions)).toBe(true);
        expect(response.body.count).toBeGreaterThan(0);
        expect(response.body.actions[0].action_type).toBe('EMERGENCY_LOCK');
        console.log('✅ Get pending actions passed');
    });
    
    test('10. Send Device Heartbeat', async () => {
        const heartbeatData = {
            battery_level: 85,
            storage_free: 1024000000,
            network_status: 'wifi'
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/device/heartbeat')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId)
            .send(heartbeatData);
        
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.pending_actions)).toBe(true);
        expect(response.body.timestamp).toBeDefined();
        console.log('✅ Device heartbeat passed');
    });
    
    test('11. Refresh Token', async () => {
        // First get a refresh token by logging in again
        const loginData = {
            username: 'testuser',
            password: 'testpassword123',
            device_id: testDeviceId
        };
        
        const loginResponse = await request(`http://localhost:${TEST_PORT}`)
            .post('/login')
            .send(loginData);
        
        const refreshToken = loginResponse.body.refresh_token;
        
        // Now refresh
        const refreshData = {
            refresh_token: refreshToken,
            device_id: testDeviceId
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/refresh')
            .send(refreshData);
        
        expect(response.status).toBe(200);
        expect(response.body.access_token).toBeDefined();
        expect(response.body.token_type).toBe('bearer');
        expect(response.body.expires_in).toBe(1800);
        console.log('✅ Token refresh passed');
    });
    
    test('12. Logout', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/logout')
            .set('Authorization', `Bearer ${testAccessToken}`)
            .set('X-Device-ID', testDeviceId);
        
        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Logged out successfully');
        console.log('✅ Logout passed');
    });
    
    test('13. Authentication Failure (Invalid Token)', async () => {
        const response = await request(`http://localhost:${TEST_PORT}`)
            .get('/device/status')
            .set('Authorization', 'Bearer invalid-token-here')
            .set('X-Device-ID', testDeviceId);
        
        expect(response.status).toBe(401);
        console.log('✅ Authentication failure test passed');
    });
    
    test('14. Rate Limiting Simulation', async () => {
        // Try to register same user multiple times
        const userData = {
            username: 'testuser',
            password: 'testpassword123',
            device_id: 'duplicate-device'
        };
        
        const response = await request(`http://localhost:${TEST_PORT}`)
            .post('/register')
            .send(userData);
        
        expect(response.status).toBe(400); // Should fail because user exists
        console.log('✅ Rate limiting/duplicate prevention works');
    });
});

console.log('🚀 Starting complete API test suite...');

// Run tests
if (require.main === module) {
    const { exec } = require('child_process');
    console.log('Running: npm test');
    exec('npm test', (error, stdout, stderr) => {
        if (error) {
            console.error('Test failed:', error);
            process.exit(1);
        }
        console.log(stdout);
        if (stderr) console.error(stderr);
    });
               }
