# Release procedure

This document describes WebAuthn4J CTAP release procedure.

### Run release workflow

Go https://github.com/webauthn4j/webauthn4j-ctap/actions/workflows/release.yml

and, run the "Release" workflow from the "Run workflow" button

This workflow automatically creates a release commit, creates a release tag, and deploys to Maven Central.
When this workflow completes successfully, the "Bump version" workflow is automatically triggered, making a commit that increments the patch version.
