# Contributing to SSHfinder

Thank you for considering contributing to SSHfinder! To ensure a smooth collaboration, please follow these guidelines:

## How to Contribute

1. Fork the repository.
2. Clone your forked repository to your local machine.
3. Create a new branch for your feature or fix.
4. Make your changes and commit them with clear and concise messages.
5. Push your changes back to your fork.
6. Open a pull request to the main repository.

## Code Style

- Use `PEP 8` conventions for Python code.
- Keep line lengths under 80 characters.
- Ensure all tests pass before submitting your PR:
  `python -m unittest discover -s tests`
- Tests must run on the standard library alone; keep new tests dependency-free
  (skip rather than fail when an optional dependency is missing).

## Issues

If you find any bugs or have feature requests, please open an issue before submitting a pull request.
