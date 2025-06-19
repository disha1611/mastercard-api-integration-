<?php

/**
 * Mastercard API Client for PHP
 * Comprehensive client for integrating with Mastercard APIs
 */
class MastercardClient {
    
    private $consumerKey;
    private $privateKeyPath;
    private $keystorePassword;
    private $environment;
    private $baseUrl;
    private $privateKey;
    
    const SANDBOX_URL = 'https://sandbox.api.mastercard.com';
    const PRODUCTION_URL = 'https://api.mastercard.com';
    
    public function __construct($config) {
        $this->consumerKey = $config['consumer_key'] ?? $_ENV['MASTERCARD_CONSUMER_KEY'];
        $this->privateKeyPath = $config['private_key_path'] ?? $_ENV['MASTERCARD_PRIVATE_KEY_PATH'];
        $this->keystorePassword = $config['keystore_password'] ?? $_ENV['MASTERCARD_KEYSTORE_PASSWORD'];
        $this->environment = $config['environment'] ?? $_ENV['MASTERCARD_ENVIRONMENT'] ?? 'sandbox';
        
        $this->baseUrl = $this->environment === 'production' ? self::PRODUCTION_URL : self::SANDBOX_URL;
        $this->privateKey = $this->loadPrivateKey();
    }
    
    /**
     * Load private key from .p12 file
     */
    private function loadPrivateKey() {
        if (!file_exists($this->privateKeyPath)) {
            throw new Exception("Private key file not found: " . $this->privateKeyPath);
        }
        
        $p12cert = file_get_contents($this->privateKeyPath);
        $certs = [];
        
        if (!openssl_pkcs12_read($p12cert, $certs, $this->keystorePassword)) {
            throw new Exception("Failed to read private key from PKCS#12 file");
        }
        
        return $certs['pkey'];
    }
    
    /**
     * Generate OAuth 1.0a signature
     */
    private function generateOAuthSignature($method, $url, $params = []) {
        $timestamp = time();
        $nonce = bin2hex(random_bytes(16));
        
        $oauthParams = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_nonce' => $nonce,
            'oauth_signature_method' => 'RSA-SHA256',
            'oauth_timestamp' => $timestamp,
            'oauth_version' => '1.0'
        ];
        
        $allParams = array_merge($oauthParams, $params);
        ksort($allParams);
        
        $paramString = http_build_query($allParams, '', '&', PHP_QUERY_RFC3986);
        $baseString = strtoupper($method) . '&' . rawurlencode($url) . '&' . rawurlencode($paramString);
        
        openssl_sign($baseString, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);
        $oauthSignature = base64_encode($signature);
        
        $oauthParams['oauth_signature'] = $oauthSignature;
        
        $authHeader = 'OAuth ';
        foreach ($oauthParams as $key => $value) {
            $authHeader .= rawurlencode($key) . '="' . rawurlencode($value) . '", ';
        }
        
        return rtrim($authHeader, ', ');
    }
    
    /**
     * Make HTTP request with OAuth authentication
     */
    private function makeRequest($method, $endpoint, $data = null) {
        $url = $this->baseUrl . $endpoint;
        
        $headers = [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: MastercardAPIClient-PHP/1.0.0'
        ];
        
        $params = [];
        if ($method === 'GET' && $data) {
            $params = $data;
            $url .= '?' . http_build_query($data);
        }
        
        $authHeader = $this->generateOAuthSignature($method, $url, $params);
        $headers[] = 'Authorization: ' . $authHeader;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        
        if ($data && in_array($method, ['POST', 'PUT', 'PATCH'])) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception("cURL Error: " . $error);
        }
        
        $decodedResponse = json_decode($response, true);
        
        if ($httpCode >= 400) {
            throw new Exception("API Error: " . ($decodedResponse['message'] ?? 'Unknown error'), $httpCode);
        }
        
        return $decodedResponse;
    }
    
    /**
     * Process a payment transaction
     */
    public function processPayment($paymentData) {
        $payload = [
            'amount' => $paymentData['amount'],
            'currency' => $paymentData['currency'] ?? 'USD',
            'paymentMethod' => [
                'type' => $paymentData['payment_method'] ?? 'card',
                'card' => [
                    'number' => $paymentData['card_number'],
                    'expiryMonth' => $paymentData['expiry_month'],
                    'expiryYear' => $paymentData['expiry_year'],
                    'securityCode' => $paymentData['security_code']
                ]
            ],
            'merchant' => [
                'id' => $paymentData['merchant_id'] ?? 'default_merchant',
                'name' => $paymentData['merchant_name'] ?? 'Test Merchant'
            ],
            'transaction' => [
                'reference' => $paymentData['transaction_reference'] ?? $this->generateTransactionId(),
                'description' => $paymentData['description'] ?? 'Payment transaction'
            ]
        ];
        
        try {
            $response = $this->makeRequest('POST', '/payments/v1/payments', $payload);
            
            return [
                'success' => true,
                'transaction_id' => $response['transactionId'],
                'status' => $response['status'],
                'amount' => $response['amount'],
                'currency' => $response['currency'],
                'timestamp' => $response['timestamp'],
                'receipt' => $response['receipt']
            ];
        } catch (Exception $e) {
            error_log("Payment processing failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Refund a transaction
     */
    public function refundTransaction($refundData) {
        $payload = [
            'originalTransactionId' => $refundData['original_transaction_id'],
            'amount' => $refundData['amount'],
            'currency' => $refundData['currency'] ?? 'USD',
            'reason' => $refundData['reason'] ?? 'Customer request'
        ];
        
        try {
            $response = $this->makeRequest('POST', '/payments/v1/refunds', $payload);
            
            return [
                'success' => true,
                'refund_id' => $response['refundId'],
                'status' => $response['status'],
                'amount' => $response['amount'],
                'timestamp' => $response['timestamp']
            ];
        } catch (Exception $e) {
            error_log("Refund processing failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Get transaction details
     */
    public function getTransaction($transactionId) {
        try {
            return $this->makeRequest('GET', "/payments/v1/transactions/{$transactionId}");
        } catch (Exception $e) {
            error_log("Failed to retrieve transaction: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Create a customer account
     */
    public function createCustomer($customerData) {
        $payload = [
            'firstName' => $customerData['first_name'],
            'lastName' => $customerData['last_name'],
            'email' => $customerData['email'],
            'phone' => $customerData['phone'],
            'address' => [
                'street' => $customerData['address']['street'] ?? '',
                'city' => $customerData['address']['city'] ?? '',
                'state' => $customerData['address']['state'] ?? '',
                'postalCode' => $customerData['address']['postal_code'] ?? '',
                'country' => $customerData['address']['country'] ?? 'US'
            ]
        ];
        
        try {
            $response = $this->makeRequest('POST', '/customers/v1/customers', $payload);
            
            return [
                'success' => true,
                'customer_id' => $response['customerId'],
                'status' => $response['status'],
                'timestamp' => $response['timestamp']
            ];
        } catch (Exception $e) {
            error_log("Customer creation failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Send money using Mastercard Send API
     */
    public function sendMoney($sendData) {
        $payload = [
            'amount' => $sendData['amount'],
            'currency' => $sendData['currency'] ?? 'USD',
            'sender' => [
                'firstName' => $sendData['sender']['first_name'],
                'lastName' => $sendData['sender']['last_name'],
                'address' => $sendData['sender']['address']
            ],
            'recipient' => [
                'firstName' => $sendData['recipient']['first_name'],
                'lastName' => $sendData['recipient']['last_name'],
                'address' => $sendData['recipient']['address'],
                'accountUri' => $sendData['recipient']['account_uri']
            ],
            'fundingSource' => $sendData['funding_source'] ?? 'credit'
        ];
        
        try {
            $response = $this->makeRequest('POST', '/send/v1/transfers', $payload);
            
            return [
                'success' => true,
                'transfer_id' => $response['transferId'],
                'status' => $response['status'],
                'amount' => $response['amount'],
                'timestamp' => $response['timestamp']
            ];
        } catch (Exception $e) {
            error_log("Money transfer failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Get account balance
     */
    public function getAccountBalance($accountId) {
        try {
            return $this->makeRequest('GET', "/accounts/v1/accounts/{$accountId}/balance");
        } catch (Exception $e) {
            error_log("Failed to get account balance: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Validate card information
     */
    public function validateCard($cardData) {
        $payload = [
            'cardNumber' => $cardData['card_number'],
            'expiryMonth' => $cardData['expiry_month'],
            'expiryYear' => $cardData['expiry_year']
        ];
        
        try {
            $response = $this->makeRequest('POST', '/validation/v1/cards/validate', $payload);
            
            return [
                'valid' => $response['valid'],
                'card_type' => $response['cardType'],
                'issuer' => $response['issuer'],
                'country' => $response['country']
            ];
        } catch (Exception $e) {
            error_log("Card validation failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Generate unique transaction ID
     */
    private function generateTransactionId() {
        return 'TXN_' . time() . '_' . strtoupper(bin2hex(random_bytes(4)));
    }
    
    /**
     * Health check for API connectivity
     */
    public function healthCheck() {
        try {
            $response = $this->makeRequest('GET', '/health/v1/status');
            
            return [
                'status' => 'healthy',
                'timestamp' => date('c'),
                'environment' => $this->environment,
                'response' => $response
            ];
        } catch (Exception $e) {
            return [
                'status' => 'unhealthy',
                'timestamp' => date('c'),
                'environment' => $this->environment,
                'error' => $e->getMessage()
            ];
        }
    }
}

// Example usage
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    try {
        // Load environment variables
        if (file_exists('.env')) {
            $env = parse_ini_file('.env');
            foreach ($env as $key => $value) {
                $_ENV[$key] = $value;
            }
        }
        
        $client = new MastercardClient([
            'consumer_key' => $_ENV['MASTERCARD_CONSUMER_KEY'],
            'private_key_path' => $_ENV['MASTERCARD_PRIVATE_KEY_PATH'],
            'keystore_password' => $_ENV['MASTERCARD_KEYSTORE_PASSWORD'],
            'environment' => 'sandbox'
        ]);
        
        // Health check
        echo "Performing health check...\n";
        $health = $client->healthCheck();
        echo "Health check result: " . json_encode($health, JSON_PRETTY_PRINT) . "\n";
        
        // Example payment processing
        echo "Processing sample payment...\n";
        $payment = $client->processPayment([
            'amount' => 100.00,
            'currency' => 'USD',
            'card_number' => '5555555555554444',
            'expiry_month' => '12',
            'expiry_year' => '2025',
            'security_code' => '123',
            'description' => 'Test payment'
        ]);
        
        echo "Payment result: " . json_encode($payment, JSON_PRETTY_PRINT) . "\n";
        
    } catch (Exception $e) {
        echo "Example execution failed: " . $e->getMessage() . "\n";
    }
}

?>
