# Testing Standards & Guidelines

## Overview

This document's purpose is to define how tests should be written and managed, for Vibe-Guard security scanner. The goal is to create tests that are reliable, easy to maintain, and reflect real security concerns.


## Core Principles

### 1. Follow TDD (Test-Driven Development)
- You should write tests before the code to guide design decisions.
- Focus on what the code should do, not how it does it.
- Don’t rewrite tests just to make them pass fix the implementation.

### 2. Keep It Clean
- Each test should serve one clear purpose.
- Avoid copy & paste: and reuse utility functions when possible.
- Use descriptive test names that explain the behavior being tested.
- Write code that’s easy to change later.

### 3. Structure and Scope
- Each test runs independently.
- Cover both normal and edge cases.
- Keep tests small and focused on one behavior.
- Avoid hard dependencies on specific test frameworks.
- Agnostic tests should run regardless of implementation. Meaning they should still pass even if the internal library or framework changes as long as the behaviour is preserved

