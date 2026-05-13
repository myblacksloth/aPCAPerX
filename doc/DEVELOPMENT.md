# Development & Contributing

## Contributing Guidelines

We welcome contributions to PCAPCaper! Please follow these guidelines to ensure smooth collaboration.

### Before You Start

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Set up your development environment (see [SETUP.md](SETUP.md))

### Code Requirements

- **Functional code**: All code must be working and tested
- **Comments**: Write clear comments in English explaining what your code does
  - Comments should be understandable without reading the actual code
- **Environment files**: Update `.env.example` if you add new configuration variables
- **Documentation**: Update relevant README or documentation files if behavior changes

### What NOT to Commit

❌ Real PCAP files  
❌ Credentials or API keys  
❌ Personal data or payloads  
❌ Sensitive information

### External Service Features

Features that send data to external services must:

✅ Be **opt-in** (not enabled by default)  
✅ Be **visible** to the user (show clear indication when data is being sent)  
✅ Be **documented** (explain what's being sent and why)  
✅ Show **consent popups** before any external request  

Examples:
- IP enrichment
- DNS reputation checks
- Advanced threat intelligence
- URLhaus lookups

### Submission Process

1. **Commit**: Use descriptive commit messages
   ```bash
   git commit -m "feat: add follow stream TCP payload reconstruction"
   git commit -m "fix: improve DNS tunneling detection"
   git commit -m "docs: clarify host aliases feature"
   ```

2. **Push**: Push your branch to your fork
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Pull Request**: Open a PR against the main repository
   - Describe what your PR does
   - Reference any related issues
   - Explain testing you've done

4. **Review**: Respond to review feedback and make adjustments as needed

### Code Style

- **Backend**: Follow PEP 8 conventions
- **Frontend**: Use TypeScript with strict mode enabled
- **Formatting**: Use Prettier for frontend code, Black for Python

### Testing

- Test your changes locally before submitting
- For backend changes, verify the API still works with the frontend
- For frontend changes, test in multiple browsers if possible
- Test with different PCAP file sizes to ensure performance

### Documentation

- Update [FEATURES.md](FEATURES.md) if adding new capabilities
- Update [CONFIGURATION.md](CONFIGURATION.md) if adding new environment variables
- Update [API.md](API.md) if adding/modifying API endpoints
- Keep [README.md](../README.md) concise; link to detailed docs in `doc/`

---

## Privacy & Security

PCAPCaper is privacy-by-default. Please maintain this principle in all contributions:

- ✅ Local analysis that doesn't contact external services
- ✅ Opt-in popups before sending data anywhere
- ✅ Filter non-global IPs before external enrichment
- ✅ Clear documentation of what data is sent where

---

## Questions or Issues?

- Check existing issues and discussions on GitHub
- Look through the documentation files in `doc/`
- Refer to the API documentation in [API.md](API.md)
