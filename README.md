
# PySniff

PySniff is an SAST CLI tool for developers designed to find security code smells or common security loopholes in Python source code. PySniff uses ASTs and rule-based detection to find code smells. After scanning, a report is generated which can be formatted in human-readable text or SARIF.

## Run Locally

Clone the project

```bash
  git clone https://github.com/debbyodungweru/pysniff.git
```

Go to the project directory

```bash
  cd pysniff
```

Create and activate a virtual environment (recommended)
```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment

# On Linux/Mac
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

Install project locally

```bash
  python -m pip install .
```

Run

```bash
  pysniff
```

## References

AST: [https://docs.python.org/3/library/ast.htm](https://docs.python.org/3/library/ast.htm)

SARIF: [https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
