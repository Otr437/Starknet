// X402 Payment Backend - Comprehensive Test Suite
// Run with: node x402-test-suite.js

const http = require('http');

const BASE_URL = 'http://localhost:3402';
const ADMIN_KEY = 'demo-admin-key-12345';

// Helper function to make HTTP requests
function makeRequest(method, path, headers = {}, body = null) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, BASE_URL);
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: JSON.parse(data)
                    });
                } catch (e) {
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: data
                    });
                }
            });
        });

        req.on('error', reject);
        
        if (body) {
            req.write(JSON.stringify(body));
        }
        
        req.end();
    });
}

// Test results tracker
const results = {
    passed: 0,
    failed: 0,
    tests: []
};

function assert(condition, testName) {
    if (condition) {
        results.passed++;
        results.tests.push({ name: testName, status: 'PASS' });
        console.log(`✅ ${testName}`);
    } else {
        results.failed++;
        results.tests.push({ name: testName, status: 'FAIL' });
        console.log(`❌ ${testName}`);
    }
}

// Generate mock transaction hashes
function generateMockUSDCTx() {
    return '0x' + Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

function generateMockZcashTx() {
    return Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

function generateMockMoneroPaymentId() {
    return Array(64).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

async function runTests() {
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('  X402 PAYMENT BACKEND - TEST SUITE');
    console.log('═══════════════════════════════════════════════════════════\n');

    // Wait for server to be ready
    console.log('⏳ Waiting for server to start...\n');
    await new Promise(resolve => setTimeout(resolve, 2000));

    // ==================== BASIC ENDPOINT TESTS ====================
    console.log('📋 Testing Basic Endpoints...\n');

    try {
        const health = await makeRequest('GET', '/api/v1/health');
        assert(health.status === 200, 'Health check returns 200');
        assert(health.body.protocol === 'x402', 'Health check returns x402 protocol');
        assert(health.body.status === 'healthy', 'Server is healthy');
    } catch (e) {
        assert(false, 'Health check accessible');
    }

    try {
        const balance = await makeRequest('GET', '/api/v1/wallet/balance');
        assert(balance.status === 200, 'Balance endpoint returns 200');
        assert(balance.body.depositWallets.usdc, 'Balance includes USDC wallets');
        assert(balance.body.depositWallets.zec, 'Balance includes ZEC wallets');
        assert(balance.body.depositWallets.xmr, 'Balance includes XMR wallet');
    } catch (e) {
        assert(false, 'Balance endpoint accessible');
    }

    try {
        const addresses = await makeRequest('GET', '/api/v1/deposit-addresses');
        assert(addresses.status === 200, 'Deposit addresses endpoint returns 200');
        assert(addresses.body.depositAddresses.usdc.address, 'USDC address provided');
        assert(addresses.body.depositAddresses.zec.shielded, 'ZEC shielded address provided');
        assert(addresses.body.depositAddresses.xmr.address, 'XMR address provided');
    } catch (e) {
        assert(false, 'Deposit addresses endpoint accessible');
    }

    try {
        const rates = await makeRequest('GET', '/api/v1/rates');
        assert(rates.status === 200, 'Rates endpoint returns 200');
        assert(rates.body.rates.ZEC > 0, 'ZEC rate is positive');
        assert(rates.body.rates.XMR > 0, 'XMR rate is positive');
    } catch (e) {
        assert(false, 'Rates endpoint accessible');
    }

    // ==================== PAYMENT VERIFICATION TESTS ====================
    console.log('\n💳 Testing Payment Verification...\n');

    try {
        const mockTx = generateMockUSDCTx();
        const verify = await makeRequest('POST', '/api/v1/payments/verify', {}, {
            currency: 'usdc',
            proof: mockTx,
            amount: 10.0,
            clientId: 'test-client-001'
        });
        assert(verify.status === 200, 'USDC payment verification returns 200');
        assert(verify.body.currency === 'USDC', 'Verification response includes currency');
        assert(typeof verify.body.verified === 'boolean', 'Verification response includes verified status');
    } catch (e) {
        assert(false, 'USDC payment verification works');
    }

    try {
        const mockTxid = generateMockZcashTx();
        const verify = await makeRequest('POST', '/api/v1/payments/verify', {}, {
            currency: 'zec',
            proof: mockTxid,
            amount: 1.0,
            clientId: 'test-client-002'
        });
        assert(verify.status === 200, 'ZEC payment verification returns 200');
        assert(verify.body.currency === 'ZEC', 'ZEC verification response correct');
    } catch (e) {
        assert(false, 'ZEC payment verification works');
    }

    try {
        const mockPaymentId = generateMockMoneroPaymentId();
        const verify = await makeRequest('POST', '/api/v1/payments/verify', {}, {
            currency: 'xmr',
            proof: mockPaymentId,
            amount: 0.5,
            clientId: 'test-client-003'
        });
        assert(verify.status === 200, 'XMR payment verification returns 200');
        assert(verify.body.currency === 'XMR', 'XMR verification response correct');
    } catch (e) {
        assert(false, 'XMR payment verification works');
    }

    // ==================== X402 PROTOCOL TESTS ====================
    console.log('\n🔒 Testing X402 Protocol (Payment-Required Endpoints)...\n');

    try {
        // Test without payment - should get 402
        const nopay = await makeRequest('GET', '/api/v1/data/premium');
        assert(nopay.status === 402, 'Premium endpoint returns 402 without payment');
        assert(nopay.body.error === 'Payment Required', 'Correct error message');
        assert(nopay.body.payment.amount.usdc === 1.0, 'Payment amount is specified');
        assert(nopay.body.payment.recipients.usdc, 'Payment recipients provided');
    } catch (e) {
        assert(false, 'Premium endpoint enforces payment');
    }

    try {
        // Test with valid payment
        const mockTx = generateMockUSDCTx();
        const withpay = await makeRequest('GET', '/api/v1/data/premium', {
            'Payment-Authorization': mockTx,
            'Payment-Currency': 'usdc',
            'Payment-Network': 'base',
            'X-Client-Id': 'test-client-004'
        });
        assert(withpay.status === 200, 'Premium endpoint returns 200 with valid payment');
        assert(withpay.body.paid === true, 'Response confirms payment');
        assert(withpay.body.protocol === 'x402', 'Response includes protocol');
    } catch (e) {
        assert(false, 'Premium endpoint accepts valid payment');
    }

    try {
        // Test MCP query without payment
        const nopay = await makeRequest('POST', '/api/v1/mcp/query', {}, {
            query: 'Test query'
        });
        assert(nopay.status === 402, 'MCP endpoint returns 402 without payment');
    } catch (e) {
        assert(false, 'MCP endpoint enforces payment');
    }

    try {
        // Test MCP query with payment
        const mockTx = generateMockUSDCTx();
        const withpay = await makeRequest('POST', '/api/v1/mcp/query', {
            'Payment-Authorization': mockTx,
            'Payment-Currency': 'usdc',
            'X-Client-Id': 'test-client-005'
        }, {
            query: 'AI test query'
        });
        assert(withpay.status === 200, 'MCP endpoint returns 200 with payment');
        assert(withpay.body.mcp_compatible === true, 'MCP compatibility confirmed');
        assert(withpay.body.response, 'MCP response provided');
    } catch (e) {
        assert(false, 'MCP endpoint accepts payment');
    }

    // ==================== PRIVACY ROUTER TESTS ====================
    console.log('\n🔐 Testing Privacy Router...\n');

    let routeId;
    try {
        const mockTx = generateMockUSDCTx();
        const route = await makeRequest('POST', '/api/v1/payments/privacy-route', {}, {
            clientId: 'privacy-test-001',
            amount: 10.0,
            currency: 'usdc',
            sourceChain: 'base',
            sourceTxHash: mockTx,
            destinationChain: 'polygon',
            destinationAddress: '0x' + Array(40).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('')
        });
        assert(route.status === 200, 'Privacy route initiation returns 200');
        assert(route.body.status === 'privacy_routing_initiated', 'Privacy routing initiated');
        assert(route.body.routeId, 'Route ID provided');
        assert(route.body.estimatedDelaySeconds > 0, 'Mixing delay estimated');
        routeId = route.body.routeId;
    } catch (e) {
        assert(false, 'Privacy route initiation works');
    }

    // Wait a bit for route to process
    await new Promise(resolve => setTimeout(resolve, 3000));

    try {
        const status = await makeRequest('GET', `/api/v1/payments/privacy-route/${routeId}/status`);
        assert(status.status === 200, 'Privacy route status returns 200');
        assert(status.body.routeId === routeId, 'Route ID matches');
        assert(['deposited', 'converting', 'shielding', 'mixing', 'unshielding', 'delivering', 'completed'].includes(status.body.status), 'Route has valid status');
        assert(status.body.transactions, 'Transaction details provided');
    } catch (e) {
        assert(false, 'Privacy route status works');
    }

    // ==================== ADMIN ENDPOINT TESTS ====================
    console.log('\n👤 Testing Admin Endpoints...\n');

    try {
        // Test without admin key
        const noauth = await makeRequest('GET', '/api/v1/admin/payments');
        assert(noauth.status === 401, 'Admin endpoint returns 401 without auth');
    } catch (e) {
        assert(false, 'Admin endpoint enforces authentication');
    }

    try {
        const payments = await makeRequest('GET', '/api/v1/admin/payments', {
            'X-Admin-Key': ADMIN_KEY
        });
        assert(payments.status === 200, 'Admin payments endpoint returns 200 with auth');
        assert(Array.isArray(payments.body.payments), 'Payments list is array');
        assert(payments.body.total >= 0, 'Total count provided');
    } catch (e) {
        assert(false, 'Admin payments endpoint works');
    }

    try {
        const routes = await makeRequest('GET', '/api/v1/admin/privacy-routes', {
            'X-Admin-Key': ADMIN_KEY
        });
        assert(routes.status === 200, 'Admin privacy routes endpoint returns 200');
        assert(Array.isArray(routes.body.routes), 'Routes list is array');
    } catch (e) {
        assert(false, 'Admin privacy routes endpoint works');
    }

    try {
        const stats = await makeRequest('GET', '/api/v1/admin/stats', {
            'X-Admin-Key': ADMIN_KEY
        });
        assert(stats.status === 200, 'Admin stats endpoint returns 200');
        assert(stats.body.payments, 'Payment stats provided');
        assert(stats.body.privacyRoutes, 'Privacy route stats provided');
        assert(typeof stats.body.payments.total === 'number', 'Total payments is number');
    } catch (e) {
        assert(false, 'Admin stats endpoint works');
    }

    // ==================== RESULTS ====================
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('  TEST RESULTS');
    console.log('═══════════════════════════════════════════════════════════\n');
    console.log(`  ✅ Passed: ${results.passed}`);
    console.log(`  ❌ Failed: ${results.failed}`);
    console.log(`  📊 Total:  ${results.passed + results.failed}`);
    console.log(`  🎯 Success Rate: ${((results.passed / (results.passed + results.failed)) * 100).toFixed(1)}%`);
    console.log('\n═══════════════════════════════════════════════════════════\n');

    if (results.failed === 0) {
        console.log('🎉 All tests passed!\n');
    } else {
        console.log('⚠️  Some tests failed. Review output above.\n');
    }

    process.exit(results.failed === 0 ? 0 : 1);
}

// Run tests
runTests().catch(err => {
    console.error('Test suite error:', err);
    process.exit(1);
});
