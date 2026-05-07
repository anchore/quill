# HSM-backed code signing with quill

This guide walks through signing macOS binaries with a private key that lives in AWS KMS — the key never exists on the
build machine, in CI logs, in container images, or in artifact storage. quill calls `kms:Sign` with a digest and
receives the signature bytes back; the rest of the signing flow (CodeDirectory hashing, CMS assembly, Mach-O patching)
runs locally as before.

## Threat model

### What HSM-backed signing protects

The **private key**. With AWS KMS the key is generated inside an AWS HSM and there is no API to extract it. Compromising
the build machine, your CI runner, container images, or any artifact you ship cannot expose the private key.

### What is — and isn't — sensitive

| Asset | Sensitive? | Why |
|---|---|---|
| KMS private key | **yes (highest)** | Lives only in AWS HSMs; never leaves. Compromise = full impersonation. |
| IAM principal with `kms:Sign` on the key | **yes** | The "private key equivalent" of this model. Lock down via IRSA / GitHub OIDC / instance profile, never long-lived access keys. Audit via CloudTrail. |
| `chain.pem` (leaf + intermediates) | **no** | Public material by definition — certificates contain only public keys plus the CA's signature. **Already embedded in every binary you ship**; any user can extract it with `codesign -d --extract-certificates /path/to/your.app`. Safe to commit to git, bake into Docker images, or fetch from any non-secret store. |
| CSR PEM | **no** | Same as the cert: public key + subject + a self-signature. |

### Threat scenarios

- *Build machine compromise (read access to `chain.pem` and source).* Attacker can verify your existing signatures —
  which any end user can already do. They cannot sign anything new without IAM credentials authorized for `kms:Sign`
  on the key.
- *Stolen `chain.pem`.* Inert without the corresponding IAM principal.
- *Stolen IAM credentials with `kms:Sign`.* Attacker can sign as you for as long as the credentials are valid. Mitigate
  with short-lived credentials (OIDC/IRSA), IAM condition keys (`aws:SourceArn`, `aws:SourceIdentity`, MFA), and
  CloudTrail alerting on unexpected `Sign` calls.
- *Compared with the P12 model.* In the existing flow, both the cert and the private key live on disk in the same
  file. Build-machine compromise = full impersonation. The KMS model removes that.

### Recommended hardening

- Scope `kms:Sign` to a single IAM role assumed only by your release workflow (e.g. a GitHub Actions OIDC trust policy
  bound to a specific repo + ref).
- Add `aws:RequestedRegion` and `aws:SourceArn` conditions to the KMS key policy.
- Enable CloudTrail data events on the key and alert on `Sign` calls outside expected windows or principals.
- Use a dedicated KMS key per environment (release vs. nightly vs. dev) so the blast radius of a stolen credential is
  bounded.

## End-to-end walkthrough

### 1. Create an asymmetric signing key in AWS KMS

In the AWS console (KMS → Customer managed keys → Create key) or via CLI:

```bash
aws kms create-key \
  --key-spec RSA_2048 \
  --key-usage SIGN_VERIFY \
  --description "quill code signing"
aws kms create-alias \
  --alias-name alias/quill-signing \
  --target-key-id <KEY_ID_FROM_PREVIOUS_STEP>
```

`RSA_2048`, `RSA_3072`, or `RSA_4096` all work. ECDSA keys are accepted by quill but not yet usable for Apple
Developer ID signing (Apple still issues RSA certificates).

### 2. Generate a CSR signed by the KMS key

Apple's normal CSR flow assumes the private key is local. Since the key lives in KMS, use quill to generate the CSR —
quill fetches the public key from KMS via `GetPublicKey` and signs the CSR itself via `kms:Sign`.

```bash
quill csr \
  --kms-key awskms:///alias/quill-signing \
  --common-name "Developer ID Application: My Org (TEAMID)" \
  --organization "My Org" \
  --organizational-unit TEAMID \
  --country US \
  --out csr.pem
```

Verify the CSR is well-formed:

```bash
openssl req -in csr.pem -verify -noout -text
```

### 3. Enroll with Apple

Sign in to [Apple Developer → Certificates](https://developer.apple.com/account/resources/certificates/list) and create
a new "Developer ID Application" certificate, uploading `csr.pem` when prompted. Download the resulting `.cer` file.

### 4. Assemble the certificate chain

Concatenate the leaf you got from Apple with the Apple intermediate and root certificates (download from
[Apple's CA page](https://www.apple.com/certificateauthority/)) into a single PEM file:

```bash
# convert Apple's DER cert to PEM
openssl x509 -inform DER -in developerid.cer -out leaf.pem

# concatenate leaf + intermediates (+ root, optional)
cat leaf.pem DeveloperIDCA.pem AppleIncRootCertificate.pem > chain.pem
```

quill also embeds Apple's intermediate and root certificates internally — if your `chain.pem` only contains the leaf,
quill will attempt to fill in the rest from its embedded store. (You can still pass `--fail-without-full-chain` to
require the file itself be complete.)

`chain.pem` is non-sensitive; commit it, bake it into your Docker image, or store it in S3 — whatever fits your build.

### 5. Sign

```bash
quill sign /path/to/my-binary \
  --kms-key awskms:///alias/quill-signing \
  --kms-cert-chain ./chain.pem
```

Verify the signature:

```bash
codesign -dv --verbose=4 /path/to/my-binary
codesign --verify --verbose=4 /path/to/my-binary
```

Notarize as you would normally:

```bash
quill notarize /path/to/my-binary
```

…or do both in one step:

```bash
quill sign-and-notarize /path/to/my-binary \
  --kms-key awskms:///alias/quill-signing \
  --kms-cert-chain ./chain.pem
```

## IAM policy

Attach to the IAM principal (role / user) that runs `quill sign` or `quill csr`. Replace the resource ARN with your
key's ARN.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "QuillSigning",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/abcd-..."
    }
  ]
}
```

`kms:DescribeKey` is **not** required — quill picks the signing algorithm from the public key type, not from KMS's
declared algorithm list (this is intentional; it pins us to PKCS#1 v1.5, which Apple Developer ID requires).

## CI integration

Use short-lived credentials. Long-lived AWS access keys defeat the purpose.

### GitHub Actions (OIDC)

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/quill-signing-release
          aws-region: us-east-1
      - run: |
          quill sign ./dist/my-app \
            --kms-key awskms:///alias/quill-signing \
            --kms-cert-chain ./chain.pem
```

The IAM trust policy on `quill-signing-release` should constrain to a specific repo and ref:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/tags/v*"
    }
  }
}
```

### EKS (IRSA) and EC2

Use IRSA service-account-bound roles on EKS, or instance profiles on EC2. Both flows are picked up automatically by the
default AWS credential chain — no quill-side configuration needed beyond `--kms-key`.

## URI reference

quill uses the same KMS URI scheme as cosign / sigstore:

| URI | Notes |
|---|---|
| `awskms:///<key-uuid>` | Bare key ID. Region from `AWS_REGION` / `~/.aws/config`. |
| `awskms:///alias/<name>` | Alias name. Region from `AWS_REGION`. |
| `awskms:///arn:aws:kms:<region>:<account>:key/<uuid>` | Key ARN. Region taken from the ARN. |
| `awskms:///arn:aws:kms:<region>:<account>:alias/<name>` | Alias ARN. Region taken from the ARN. |
| `awskms://<endpoint>/<key-id>` | Custom endpoint (e.g. LocalStack). |

GCP KMS (`gcpkms://`) and Azure Key Vault (`azurekms://`) are planned as additional providers; the URI scheme is the
same for all of them.

## Validating quill's KMS code path against Apple

Two layers of validation:

**Per-PR (automatic, no setup):** the `TestSign_KMS` test in `quill/sign_test.go`'s sister
file routes the existing trusted-fixture cert chains through an in-process fake KMS provider
holding the same RSA key. It asserts the resulting Mach-O has byte-identical CodeDirectory +
CMS to the P12 path and passes `codesign --verify`. Run as part of normal `go test ./...` —
catches any regression that changes the KMS code path's output.

**Pre-release (manual dispatch):** the `Apple E2E (KMS)` workflow at
`.github/workflows/apple-e2e-kms.yaml` performs the full Apple round-trip — real KMS key,
real Developer ID cert, real `quill notarize` against Apple's Notary service. This is the
only test that proves Apple actually accepts a CMS we built around a KMS-resident key. Run
before tagging a release by dispatching the workflow from the Actions tab.

The workflow is `workflow_dispatch` only (not `pull_request`) because Apple Notary has rate
limits, occasional outages, and 1-5+ minute submission latency that would make per-PR runs
flaky and slow. The unit-level `TestSign_KMS` covers per-PR regressions.

### One-time setup for the Apple E2E workflow

This setup must be done once, by a human, before the workflow can run:

1. **Create the KMS key.**
   ```bash
   aws kms create-key --key-spec RSA_2048 --key-usage SIGN_VERIFY \
     --description "quill CI signing key"
   aws kms create-alias --alias-name alias/quill-ci-signing \
     --target-key-id <KEY_ID>
   ```

2. **Create an IAM role for the workflow.** Use the IAM policy from the section above
   (`kms:Sign`, `kms:GetPublicKey`). The trust policy should bind to GitHub OIDC for this
   repo, restricted to `workflow_dispatch` events from the default branch:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "Federated": "arn:aws:iam::<ACCOUNT>:oidc-provider/token.actions.githubusercontent.com" },
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {
         "StringEquals": {
           "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
         },
         "StringLike": {
           "token.actions.githubusercontent.com:sub": "repo:<ORG>/<REPO>:ref:refs/heads/main"
         }
       }
     }]
   }
   ```

3. **Generate a CSR locally and submit to Apple.** Build quill with these changes, then:
   ```bash
   quill csr --kms-key awskms:///alias/quill-ci-signing \
     --common-name "Developer ID Application: <Org Name> (<TEAMID>)" \
     --organization "<Org Name>" --organizational-unit <TEAMID> --country US \
     --out csr.pem
   ```
   Submit `csr.pem` at <https://developer.apple.com/account/resources/certificates/list>,
   download the issued cert, and assemble `chain.pem` (leaf + Apple intermediate + Apple root).

4. **Configure repo state.** In repo Settings → Secrets and variables → Actions:

   **Variables (non-secret — these are public material):**
   - `QUILL_KMS_KEY_URI` → e.g. `awskms:///alias/quill-ci-signing`
   - `QUILL_KMS_CERT_CHAIN_PEM` → paste the full multi-line PEM contents of `chain.pem`
   - `AWS_KMS_SIGNING_ROLE_ARN` → ARN of the IAM role from step 2
   - `AWS_KMS_REGION` → e.g. `us-east-1`

   **Secrets (already present from existing release flow):**
   - `APPLE_NOTARY_ISSUER`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_KEY`

5. **Dispatch the workflow** from the Actions tab to confirm everything is wired correctly.

### What the workflow does (per run)

1. Assumes the AWS IAM role via OIDC.
2. Materializes `chain.pem` from the repo Variable.
3. Builds a quill snapshot.
4. Runs `quill csr` against the KMS key — confirms `GetPublicKey` + `Sign` still work.
5. Signs a copy of the freshly-built quill binary using the KMS key + cert chain.
6. Runs `codesign --verify --strict --deep` to confirm the signature parses + validates.
7. Submits to Apple Notary via `quill notarize --wait` — fails the job if Apple rejects.
8. Uploads the signed-and-notarized binary as a workflow artifact for manual inspection.

## Troubleshooting

### `KMS public key does not match any certificate in the chain`

The `chain.pem` you provided was issued for a different key. This usually means the CSR was generated against one KMS
key but the cert was downloaded for a different one. Re-run `quill csr` against the same key you'll be signing with.

### `KMS Sign … AccessDeniedException`

The IAM principal lacks `kms:Sign` permission on the key. Check the key policy and the principal's IAM policy. CloudTrail
will show the rejected call with the exact principal ARN.

### `failed to verify certificate chain`

`chain.pem` is missing intermediates or has them in the wrong order, and quill couldn't fill in from its embedded Apple
store either. Re-download the Apple intermediate / root from
[Apple's CA page](https://www.apple.com/certificateauthority/) and re-concatenate.

### Signature works, but Gatekeeper rejects with "modified or invalid"

quill pins the KMS signing algorithm to `RSASSA_PKCS1_V1_5_SHA_256` (matching Apple Developer ID's expectations). If you
manually bypass that — e.g. by modifying quill — and produce a PSS signature, Gatekeeper will reject the binary because
the CMS SignerInfo OID disagrees with the actual signature scheme.
