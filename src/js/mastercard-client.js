const axios = require('axios');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
const fs = require('fs');
const forge = require('node-forge');
require('dotenv').config();

/**
 * Mastercard API Client
 * Comprehensive client for integrating with Mastercard APIs
 */
class MastercardClient {
    constructor(config) {
        this.consumerKey = config.consumerKey || process.env.MASTERCARD_CONSUMER_KEY;
        this.privateKeyPath = config.privateKeyPath || process.env.MASTERCARD_PRIVATE_KEY_PATH;
        this.keystorePassword = config.keystorePassword || process.env.MASTERCARD_KEYSTORE_PASSWORD;
        this.environment = config.environment || process.env.MASTERCARD_ENVIRONMENT || 'sandbox';
        
        // Base URLs for different environments
        this.baseUrls = {
            sandbox: 'https://sandbox.api.mastercard.com',
            production: 'https://api.mastercard.com'
        };
        
        this.baseUrl = this.baseUrls[this.environment];
        this.privateKey = this.loadPrivateKey();
        this.oauth = this.setupOAuth();
        
        // Setup axios instance with default configurations
        this.httpClient = axios.create({
            baseURL: this.baseUrl,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'MastercardAPIClient/1.0.0'
            }
        });
        
        this.setupInterceptors();
    }
    
    /**
     * Load private key from .p12 file
     */
    loadPrivateKey() {
        try {
            const p12Buffer = fs.readFileSync(this.privateKeyPath);
            const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
            const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, this.keystorePassword);
            
            const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
            const bag = bags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
            
            return forge.pki.privateKeyToPem(bag.key);
        } catch (error) {
            throw new Error(`Failed to load private key: ${error.message}`);
        }
    }
    
    /**
     * Setup OAuth 1.0a authentication
     */
    setupOAuth() {
        return OAuth({
            consumer: { key: this.consumerKey, secret: '' },
            signature_method: 'RSA-SHA256',
            hash_function(base_string, key) {
                const sign = crypto.createSign('RSA-SHA256');
                sign.update(base_string);
                return sign.sign(key, 'base64');
            }
        });
    }
    
    /**
     * Setup HTTP interceptors for request/response handling
     */
    setupInterceptors() {
        // Request interceptor for OAuth signing
        this.httpClient.interceptors.request.use(
            (config) => {
                const requestData = {
                    url: `${this.baseUrl}${config.url}`,
                    method: config.method.toUpperCase(),
                    data: config.data
                };
                
                const authHeader = this.oauth.toHeader(
                    this.oauth.authorize(requestData, { key: this.privateKey, secret: '' })
                );
                
                config.headers.Authorization = authHeader.Authorization;
                
                console.log(`Making ${config.method.toUpperCase()} request to: ${config.url}`);
                return config;
            },
            (error) => {
                console.error('Request interceptor error:', error);
                return Promise.reject(error);
            }
        );
        
        // Response interceptor for error handling
        this.httpClient.interceptors.response.use(
            (response) => {
                console.log(`Response received with status: ${response.status}`);
                return response;
            },
            (error) => {
                console.error('API Error:', error.response?.data || error.message);
                return Promise.reject(this.handleApiError(error));
            }
        );
    }
    
    /**
     * Handle API errors with detailed error information
     */
    handleApiError(error) {
        if (error.response) {
            const { status, data } = error.response;
            return {
                status,
                message: data.message || 'API request failed',
                details: data.details || data,
                timestamp: new Date().toISOString()
            };
        }
        
        return {
            status: 500,
            message: error.message || 'Network error',
            timestamp: new Date().toISOString()
        };
    }
    
    /**
     * Process a payment transaction
     */
    async processPayment(paymentData) {
        try {
            const payload = {
                amount: paymentData.amount,
                currency: paymentData.currency || 'USD',
                paymentMethod: {
                    type: paymentData.paymentMethod || 'card',
                    card: {
                        number: paymentData.cardNumber,
                        expiryMonth: paymentData.expiryMonth,
                        expiryYear: paymentData.expiryYear,
                        securityCode: paymentData.securityCode
                    }
                },
                merchant: {
                    id: paymentData.merchantId || 'default_merchant',
                    name: paymentData.merchantName || 'Test Merchant'
                },
                transaction: {
                    reference: paymentData.transactionReference || this.generateTransactionId(),
                    description: paymentData.description || 'Payment transaction'
                }
            };
            
            const response = await this.httpClient.post('/payments/v1/payments', payload);
            
            return {
                success: true,
                transactionId: response.data.transactionId,
                status: response.data.status,
                amount: response.data.amount,
                currency: response.data.currency,
                timestamp: response.data.timestamp,
                receipt: response.data.receipt
            };
            
        } catch (error) {
            console.error('Payment processing failed:', error);
            throw error;
        }
    }
    
    /**
     * Refund a transaction
     */
    async refundTransaction(refundData) {
        try {
            const payload = {
                originalTransactionId: refundData.originalTransactionId,
                amount: refundData.amount,
                currency: refundData.currency || 'USD',
                reason: refundData.reason || 'Customer request'
            };
            
            const response = await this.httpClient.post('/payments/v1/refunds', payload);
            
            return {
                success: true,
                refundId: response.data.refundId,
                status: response.data.status,
                amount: response.data.amount,
                timestamp: response.data.timestamp
            };
        } catch (error) {
            console.error('Refund processing failed:', error);
            throw error;
        }
    }
    
    /**
     * Get transaction details
     */
    async getTransaction(transactionId) {
        try {
            const response = await this.httpClient.get(`/payments/v1/transactions/${transactionId}`);
            return response.data;
        } catch (error) {
            console.error('Failed to retrieve transaction:', error);
            throw error;
        }
    }
    
    /**
     * Create a customer account
     */
    async createCustomer(customerData) {
        try {
            const payload = {
                firstName: customerData.firstName,
                lastName: customerData.lastName,
                email: customerData.email,
                phone: customerData.phone,
                address: {
                    street: customerData.address?.street,
                    city: customerData.address?.city,
                    state: customerData.address?.state,
                    postalCode: customerData.address?.postalCode,
                    country: customerData.address?.country || 'US'
                }
            };
            
            const response = await this.httpClient.post('/customers/v1/customers', payload);
            
            return {
                success: true,
                customerId: response.data.customerId,
                status: response.data.status,
                timestamp: response.data.timestamp
            };
        } catch (error) {
            console.error('Customer creation failed:', error);
            throw error;
        }
    }
    
    /**
     * Send money using Mastercard Send API
     */
    async sendMoney(sendData) {
        try {
            const payload = {
                amount: sendData.amount,
                currency: sendData.currency || 'USD',
                sender: {
                    firstName: sendData.sender.firstName,
                    lastName: sendData.sender.lastName,
                    address: sendData.sender.address
                },
                recipient: {
                    firstName: sendData.recipient.firstName,
                    lastName: sendData.recipient.lastName,
                    address: sendData.recipient.address,
                    accountUri: sendData.recipient.accountUri
                },
                fundingSource: sendData.fundingSource || 'credit'
            };
            
            const response = await this.httpClient.post('/send/v1/transfers', payload);
            
            return {
                success: true,
                transferId: response.data.transferId,
                status: response.data.status,
                amount: response.data.amount,
                timestamp: response.data.timestamp
            };
        } catch (error) {
            console.error('Money transfer failed:', error);
            throw error;
        }
    }
    
    /**
     * Get account balance
     */
    async getAccountBalance(accountId) {
        try {
            const response = await this.httpClient.get(`/accounts/v1/accounts/${accountId}/balance`);
            return response.data;
        } catch (error) {
            console.error('Failed to get account balance:', error);
            throw error;
        }
    }
    
    /**
     * Validate card information
     */
    async validateCard(cardData) {
        try {
            const payload = {
                cardNumber: cardData.cardNumber,
                expiryMonth: cardData.expiryMonth,
                expiryYear: cardData.expiryYear
            };
            
            const response = await this.httpClient.post('/validation/v1/cards/validate', payload);
            
            return {
                valid: response.data.valid,
                cardType: response.data.cardType,
                issuer: response.data.issuer,
                country: response.data.country
            };
        } catch (error) {
            console.error('Card validation failed:', error);
            throw error;
        }
    }
    
    /**
     * Generate unique transaction ID
     */
    generateTransactionId() {
        return `TXN_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    }
    
    /**
     * Health check for API connectivity
     */
    async healthCheck() {
        try {
            const response = await this.httpClient.get('/health/v1/status');
            return {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                environment: this.environment,
                response: response.data
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                environment: this.environment,
                error: error.message
            };
        }
    }
}

module.exports = MastercardClient;

// Example usage
if (require.main === module) {
    (async () => {
        try {
            const client = new MastercardClient({
                consumerKey: process.env.MASTERCARD_CONSUMER_KEY,
                privateKeyPath: process.env.MASTERCARD_PRIVATE_KEY_PATH,
                keystorePassword: process.env.MASTERCARD_KEYSTORE_PASSWORD,
                environment: 'sandbox'
            });
            
            // Health check
            console.log('Performing health check...');
            const health = await client.healthCheck();
            console.log('Health check result:', health);
            
            // Example payment processing
            console.log('Processing sample payment...');
            const payment = await client.processPayment({
                amount: 100.00,
                currency: 'USD',
                cardNumber: '5555555555554444',
                expiryMonth: '12',
                expiryYear: '2025',
                securityCode: '123',
                description: 'Test payment'
            });
            
            console.log('Payment result:', payment);
            
        } catch (error) {
            console.error('Example execution failed:', error);
        }
    })();
}
