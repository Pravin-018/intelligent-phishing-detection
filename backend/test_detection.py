from backend.detection_engine import analyze_email, analyze_url


def test_url_detection_flags_shortened_malicious_shape():
    result = analyze_url('https://bit.ly/verify-paypal-secure-login')
    assert result['risk_score'] >= 20
    assert 'URL Shortener' in [indicator['name'] for indicator in result['indicators']]


def test_email_detection_flags_urgent_credentials_request():
    payload = {
        'subject': 'Urgent: Account verification required',
        'sender_email': 'security@paypa1-update.com',
        'display_name': 'PayPal Security Team',
        'reply_to': 'noreply@mailer.com',
        'message': 'Your account has been suspended. Verify immediately. Provide your password and OTP to avoid service interruption.',
        'manual_url': 'https://bit.ly/verify-paypal-secure-login',
    }
    result = analyze_email(payload)
    assert result['risk_score'] >= 60
    assert 'Urgent or Threatening Language' in [indicator['name'] for indicator in result['indicators']]
    assert 'Credential or Financial Request' in [indicator['name'] for indicator in result['indicators']]
