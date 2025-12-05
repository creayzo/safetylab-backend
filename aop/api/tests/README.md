# AOP Test Suite

Comprehensive test suite for the Agent Observability Platform covering unit tests, integration tests, reproducibility tests, and security tests.

## Test Structure

```
api/tests/
├── __init__.py
├── test_serializers.py       # Parser/serializer unit tests
├── test_signature.py          # Signature verification & key rotation
├── test_idempotency.py        # Idempotency & WAL tests
├── test_integration.py        # End-to-end integration tests
├── test_reproducibility.py   # Replay & determinism tests
└── test_security.py           # Security & RBAC tests
```

## Running Tests

### Run All Tests
```bash
cd aop
python manage.py test api.tests
```

### Run Specific Test Module
```bash
# Serializer tests
python manage.py test api.tests.test_serializers

# Signature verification tests
python manage.py test api.tests.test_signature

# Idempotency tests
python manage.py test api.tests.test_idempotency

# Integration tests
python manage.py test api.tests.test_integration

# Reproducibility tests
python manage.py test api.tests.test_reproducibility

# Security tests
python manage.py test api.tests.test_security
```

### Run Specific Test Class
```bash
python manage.py test api.tests.test_serializers.ToonPayloadFieldTest
python manage.py test api.tests.test_signature.SignatureVerifierTest
python manage.py test api.tests.test_integration.EndToEndEventFlowTest
```

### Run With Verbose Output
```bash
python manage.py test api.tests --verbosity=2
```

### Run With Coverage
```bash
pip install coverage
coverage run --source='api' manage.py test api.tests
coverage report
coverage html  # Generates HTML report in htmlcov/
```

## Test Categories

### 1. Parser & Serializer Tests (`test_serializers.py`)

**ToonPayloadFieldTest**
- ✅ Dict to JSON string conversion
- ✅ JSON string validation
- ✅ Invalid JSON handling
- ✅ Type validation
- ✅ Representation conversion

**TraceEventSerializerTest**
- ✅ Valid event serialization
- ✅ Missing required fields
- ✅ Invalid choice values (actor, type)
- ✅ Sequence number validation
- ✅ Meta field validation
- ✅ UUID format validation
- ✅ Timestamp parsing

**EdgeCaseTests**
- ✅ Very large payloads
- ✅ Unicode characters
- ✅ Deeply nested structures
- ✅ Empty payloads

### 2. Signature Verification Tests (`test_signature.py`)

**SignatureVerifierTest**
- ✅ Signature generation
- ✅ Valid signature verification
- ✅ Invalid signature rejection
- ✅ Payload tampering detection
- ✅ Sequence tampering detection
- ✅ Timestamp tampering detection
- ✅ Cross-key verification failure
- ✅ Deterministic signature generation
- ✅ Special character handling

**KeyRotationTest**
- ✅ Salt key creation
- ✅ Key rotation mechanics
- ✅ Old key verification (grace period)
- ✅ Expired key rejection
- ✅ Multiple consecutive rotations
- ✅ Active key retrieval

**APIKeyAuthenticationTest**
- ✅ API key creation
- ✅ Valid key authentication
- ✅ Invalid key rejection
- ✅ Inactive key rejection
- ✅ Expired key rejection
- ✅ Key revocation
- ✅ Last used timestamp update

### 3. Idempotency Tests (`test_idempotency.py`)

**IdempotencyTest**
- ✅ WAL entry creation
- ✅ Duplicate key prevention
- ✅ Duplicate detection within run
- ✅ Same seq in different runs allowed
- ✅ IdempotencyLog tracking
- ✅ Attempt count incrementing
- ✅ WAL status transitions
- ✅ Failed status with retry
- ✅ Max retry enforcement
- ✅ Event ordering
- ✅ Old entry cleanup

**WALProcessingTest**
- ✅ Pending entry processing
- ✅ Concurrent processing prevention
- ✅ Batch processing

### 4. Integration Tests (`test_integration.py`)

**EndToEndEventFlowTest**
- ✅ Full event ingestion flow (client → WAL → TraceEvent)
- ✅ Multiple events sequential ingestion
- ✅ Duplicate event rejection
- ✅ Signature verification failure
- ✅ Evaluation trigger on run completion

**EvaluationPipelineTest**
- ✅ Evaluation run creation
- ✅ Policy validator invocation
- ✅ PII detector invocation
- ✅ Evaluation result storage

**BackpressureTest**
- ✅ WAL queue depth monitoring
- ✅ Per-organization rate limiting

**StreamingModeTest**
- ✅ Immediate event availability
- ✅ WebSocket notification

### 5. Reproducibility Tests (`test_reproducibility.py`)

**ReplaySnapshotTest**
- ✅ Replay snapshot creation
- ✅ Seed storage
- ✅ Model parameter storage

**LLMResponseCachingTest**
- ✅ LLM response caching
- ✅ Prompt hashing consistency
- ✅ Cached response retrieval
- ✅ Cache expiration
- ✅ Consent requirement

**ToolResponseCachingTest**
- ✅ Tool response caching
- ✅ Parameter hashing consistency
- ✅ Cached tool response retrieval

**DeterministicReplayTest**
- ✅ Full replay with caching
- ✅ Seed determinism verification
- ✅ Comparison report generation
- ✅ Divergence detection

**ReplayModesTest**
- ✅ Full mode (all cached)
- ✅ Hybrid mode (tools cached, LLM re-run)
- ✅ Verification mode (nothing cached)

### 6. Security Tests (`test_security.py`)

**HMACTamperingTest**
- ✅ Payload tampering detection
- ✅ Sequence tampering detection
- ✅ Timestamp tampering detection
- ✅ Actor tampering detection
- ✅ Replay attack prevention

**KeyRotationSecurityTest**
- ✅ Old signatures invalid post-rotation
- ✅ Grace period support
- ✅ Audit trail creation

**RBACTest**
- ✅ Organization isolation
- ✅ API key scope restrictions
- ✅ Cross-agent access prevention

**APIAuthenticationTest**
- ✅ Missing API key rejection
- ✅ Invalid API key rejection
- ✅ Valid API key acceptance

**SecurityPolicyTest**
- ✅ Blocked action detection
- ✅ Allowed action permission
- ✅ PII detection in payloads

**MTLSSecurityTest**
- ✅ Certificate creation
- ✅ Expired certificate detection
- ✅ Revoked certificate rejection

**RateLimitingSecurityTest**
- ✅ Rate limit threshold detection

**InputValidationSecurityTest**
- ✅ Oversized payload rejection
- ✅ SQL injection prevention
- ✅ XSS prevention

## Test Coverage Goals

- **Serializers**: 100% coverage
- **Signature verification**: 100% coverage
- **Idempotency**: 95%+ coverage
- **Integration**: 90%+ coverage (excludes external dependencies)
- **Reproducibility**: 95%+ coverage
- **Security**: 95%+ coverage

## Continuous Integration

### GitHub Actions Example

```yaml
name: Django Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: aop_test
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install coverage
      
      - name: Run migrations
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/aop_test
          REDIS_URL: redis://localhost:6379
        run: |
          cd aop
          python manage.py migrate
      
      - name: Run tests with coverage
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/aop_test
          REDIS_URL: redis://localhost:6379
        run: |
          cd aop
          coverage run --source='api' manage.py test api.tests
          coverage report
          coverage xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./aop/coverage.xml
```

## Test Data Fixtures

Create test fixtures for common scenarios:

```bash
# Export test data
python manage.py dumpdata api.Organization api.Agent --indent 2 > fixtures/test_orgs.json

# Load test data
python manage.py loaddata fixtures/test_orgs.json
```

## Mocking External Dependencies

Tests use mocking for external services:

```python
from unittest.mock import patch, MagicMock

# Mock LLM API calls
@patch('api.llm_client.OpenAI.chat.completions.create')
def test_llm_integration(self, mock_llm):
    mock_llm.return_value = MagicMock(
        choices=[{"message": {"content": "Mocked response"}}]
    )
    # Test code here

# Mock S3 operations
@patch('boto3.client')
def test_s3_upload(self, mock_boto):
    mock_s3 = MagicMock()
    mock_boto.return_value = mock_s3
    # Test code here

# Mock Celery tasks
@patch('api.tasks.evaluate_run.delay')
def test_evaluation_trigger(self, mock_task):
    mock_task.return_value = MagicMock(id='task-123')
    # Test code here
```

## Performance Testing

### Load Testing

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/load_test.py --host=http://localhost:8000
```

### Database Query Optimization

```python
from django.test.utils import override_settings
from django.db import connection
from django.test.utils import CaptureQueriesContext

def test_query_efficiency(self):
    """Test that endpoint makes minimal database queries."""
    with CaptureQueriesContext(connection) as queries:
        # Your test code
        response = self.client.get('/api/runs/')
    
    # Assert reasonable query count
    self.assertLess(len(queries), 10)
```

## Debugging Failed Tests

### Enable detailed output
```bash
python manage.py test api.tests --verbosity=3 --debug-mode
```

### Run specific failing test
```bash
python manage.py test api.tests.test_integration.EndToEndEventFlowTest.test_full_event_ingestion_flow
```

### Use Django shell for debugging
```bash
python manage.py shell
>>> from api.tests.test_serializers import *
>>> test = ToonPayloadFieldTest()
>>> test.setUp()
>>> test.test_dict_to_internal_value()
```

## Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Use `setUp()` and `tearDown()` for test data
3. **Mocking**: Mock external services (LLM APIs, S3, etc.)
4. **Assertions**: Use specific assertions (`assertEqual`, `assertIn`, etc.)
5. **Coverage**: Aim for >90% code coverage
6. **Documentation**: Document complex test scenarios
7. **Speed**: Keep unit tests fast (<1s each)
8. **Fixtures**: Use fixtures for common test data

## Troubleshooting

### Database Issues
```bash
# Reset test database
python manage.py flush --database=test

# Run migrations for test DB
python manage.py migrate --database=test
```

### Redis Issues
```bash
# Clear Redis cache
redis-cli FLUSHALL

# Check Redis connection
redis-cli PING
```

### Import Errors
```bash
# Verify Python path
python -c "import sys; print('\n'.join(sys.path))"

# Install missing dependencies
pip install -r requirements.txt
```

## Test Metrics

Current test statistics:
- **Total tests**: 100+
- **Unit tests**: 70+
- **Integration tests**: 15+
- **Security tests**: 15+
- **Average execution time**: ~30 seconds
- **Code coverage**: Target 90%+

## Contributing

When adding new features:
1. Write tests first (TDD)
2. Ensure all tests pass
3. Maintain >90% coverage
4. Document test scenarios
5. Update this README

## Contact

For test-related questions, contact the development team.
