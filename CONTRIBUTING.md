# Contributing to AI Firewall Classification System

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion:
1. Check if the issue already exists in [Issues](https://github.com/IkuzoMyDream/AI-Firewall-Classification-System/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - System information (OS, Python version, etc.)

### Submitting Changes

1. **Fork the repository**
   ```bash
   git clone https://github.com/IkuzoMyDream/AI-Firewall-Classification-System.git
   cd AI-Firewall-Classification-System
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation if needed

4. **Test your changes**
   ```bash
   # Test data collection
   python src/data_collector.py --targets 192.168.56.10 --repeat 5 --output test.csv
   
   # Test classification
   python src/classify.py 192.168.56.10
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: Brief description of changes"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Select your feature branch
   - Describe your changes clearly

## Code Guidelines

### Python Code Style
- Follow PEP 8 style guide
- Use meaningful variable names
- Add docstrings to functions
- Keep functions focused and small

### Example:
```python
def parse_ping(output: Optional[str]) -> Dict[str, Any]:
    """
    Parse ping output to extract network features.
    
    Args:
        output: Raw ping command output
        
    Returns:
        Dictionary with avg_latency, packet_loss, ttl_return, icmp_reachable
    """
    # Implementation
    pass
```

### Documentation
- Update README.md if adding new features
- Add examples for new functionality
- Keep documentation clear and concise

## Areas for Contribution

### High Priority
- [ ] Add support for more firewall types (pfSense, Fortinet, Palo Alto)
- [ ] Implement ensemble models (XGBoost, LightGBM)
- [ ] Add IPv6 support
- [ ] Create web interface for classification

### Medium Priority
- [ ] Add unit tests
- [ ] Improve error handling
- [ ] Add logging functionality
- [ ] Optimize feature collection speed

### Low Priority
- [ ] Add Jupyter notebook tutorials
- [ ] Create Docker container
- [ ] Add CI/CD pipeline
- [ ] Multilingual documentation

## Testing

Before submitting a PR, ensure:
1. Data collection works on all VM types
2. Classification produces correct results
3. No syntax errors or import issues
4. Documentation is updated

## Questions?

Feel free to:
- Open an issue with the "question" label
- Contact: [GitHub Profile](https://github.com/IkuzoMyDream)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
