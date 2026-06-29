import AuthenticationServices
import SwiftUI
import LocalAuthentication
import CryptoKit

// Passkey (WebAuthn) support for the AutoFill credential provider. Kept in a separate file as a
// class extension so the working password flow stays untouched. The ASCredentialRequest /
// ASPasskey* APIs are macOS 14+ only; the deployment target is already 14.0, and the
// @available(macOS 14.0, *) gate is kept for explicitness.
//
// NOTE: This code path requires a device + a real relying party to verify; it cannot be unit
// tested here. The byte-level crypto it relies on (Fido2) IS validated by tests.

@available(macOS 14.0, *)
extension CredentialProviderViewController {

    // MARK: - Unified entry points (macOS 14+)

    /// Silent provider for both passwords and passkeys. We always need user verification / the
    /// app-side session, so defer to the UI path.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        passkeyCancel(.userInteractionRequired)
    }

    /// UI provider, routed by request type. Passwords reuse the existing password UI so that flow
    /// keeps working on macOS 14.
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        if credentialRequest.type == .passkeyAssertion, let req = credentialRequest as? ASPasskeyCredentialRequest {
            presentPasskeyAssertion(req)
            return
        }
        if let id = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity {
            prepareInterfaceToProvideCredential(for: id)   // existing password override
            return
        }
        passkeyCancel(.failed)
    }

    /// Create a new passkey for a relying party.
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let req = registrationRequest as? ASPasskeyCredentialRequest else { passkeyCancel(.failed); return }
        presentPasskeyRegistration(req)
    }

    // MARK: - Assertion (login)

    private func presentPasskeyAssertion(_ req: ASPasskeyCredentialRequest) {
        guard let accountId = KeychainService.shared.activeAccountId else { passkeyCancel(.userInteractionRequired); return }
        let identity = req.credentialIdentity as? ASPasskeyCredentialIdentity
        let credentialID = identity?.credentialID ?? Data()
        passkeyPresent(PasskeyAuthView(reason: L10n.AutoFill.repromptReason.localized,
                                       onCancel: { [weak self] in self?.passkeyCancel(.userCanceled) },
                                       onVerified: { [weak self] context in
            self?.completeAssertion(req: req, accountId: accountId, credentialID: credentialID, context: context)
        }))
    }

    private func completeAssertion(req: ASPasskeyCredentialRequest, accountId: String, credentialID: Data, context: LAContext) {
        let store = PasskeyStore.forAccount(accountId)
        guard let cred = store.credential(credentialId: credentialID, context: context),
              let key = try? P256.Signing.PrivateKey(rawRepresentation: cred.privateKey) else {
            passkeyCancel(.credentialIdentityNotFound); return
        }
        let counter = store.bumpCounter(credentialId: credentialID, context: context)
        let authData = Fido2.authenticatorData(
            rpId: cred.rpId,
            flags: Fido2.Flags.userPresent | Fido2.Flags.userVerified,
            signCount: counter, attestedCredentialData: nil)
        guard let signature = try? Fido2.assertionSignature(
            privateKey: key, authenticatorData: authData, clientDataHash: req.clientDataHash) else {
            passkeyCancel(.failed); return
        }
        let assertion = ASPasskeyAssertionCredential(
            userHandle: cred.userHandle, relyingParty: cred.rpId, signature: signature,
            clientDataHash: req.clientDataHash, authenticatorData: authData, credentialID: cred.credentialId)
        extensionContext.completeAssertionRequest(using: assertion, completionHandler: nil)
    }

    // MARK: - Registration (create)

    private func presentPasskeyRegistration(_ req: ASPasskeyCredentialRequest) {
        guard let accountId = KeychainService.shared.activeAccountId,
              let identity = req.credentialIdentity as? ASPasskeyCredentialIdentity else {
            passkeyCancel(.userInteractionRequired); return
        }
        passkeyPresent(PasskeyAuthView(reason: L10n.AutoFill.repromptReason.localized,
                                       onCancel: { [weak self] in self?.passkeyCancel(.userCanceled) },
                                       onVerified: { [weak self] context in
            self?.completeRegistration(req: req, accountId: accountId, identity: identity, context: context)
        }))
    }

    private func completeRegistration(req: ASPasskeyCredentialRequest, accountId: String, identity: ASPasskeyCredentialIdentity, context: LAContext) {
        guard let (cred, key) = try? Fido2.createCredential(
            rpId: identity.relyingPartyIdentifier, userHandle: identity.userHandle, userName: identity.userName) else {
            // CSPRNG failure — never register a credential with a predictable id.
            passkeyCancel(.failed); return
        }
        PasskeyStore.forAccount(accountId).add(cred, context: context)

        let (x, y) = Fido2.coordinates(key.publicKey)
        let cose = Fido2.coseKey(x: x, y: y)
        let acd = Fido2.attestedCredentialData(aaguid: Data(count: 16), credentialId: cred.credentialId, coseKey: cose)
        let authData = Fido2.authenticatorData(
            rpId: cred.rpId,
            flags: Fido2.Flags.userPresent | Fido2.Flags.userVerified | Fido2.Flags.attestedCredentialData,
            signCount: 0, attestedCredentialData: acd)
        let attestationObject = Fido2.attestationObject(authData: authData)

        // Register the new passkey so the OS offers it next time.
        let asIdentity = ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: cred.rpId, userName: cred.userName,
            credentialID: cred.credentialId, userHandle: cred.userHandle, recordIdentifier: nil)
        ASCredentialIdentityStore.shared.saveCredentialIdentities([asIdentity], completion: nil)

        let registration = ASPasskeyRegistrationCredential(
            relyingParty: cred.rpId, clientDataHash: req.clientDataHash,
            credentialID: cred.credentialId, attestationObject: attestationObject)
        extensionContext.completeRegistrationRequest(using: registration, completionHandler: nil)
    }

    // MARK: - Helpers

    private func passkeyCancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    private func passkeyPresent(_ rootView: some View) {
        let hosting = NSHostingController(rootView: rootView)
        addChild(hosting)
        hosting.view.frame = view.bounds
        hosting.view.autoresizingMask = [.width, .height]
        view.addSubview(hosting.view)
    }
}

// MARK: - User-verification UI

/// Minimal view that performs device-owner authentication (Touch ID / device password) before a
/// passkey assertion or registration. Fails closed: no auth available → cancel.
struct PasskeyAuthView: View {
    let reason: String
    let onCancel: () -> Void
    let onVerified: (LAContext) -> Void

    @State private var errorText: String?

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "person.badge.key.fill").font(.system(size: 40)).foregroundColor(.accentColor)
            Text("VaultGuard").font(.system(size: 17, weight: .bold))
            if let errorText {
                Text(errorText).font(.system(size: 12)).foregroundColor(.red).multilineTextAlignment(.center)
                Button(L10n.cancel.localized) { onCancel() }.buttonStyle(.borderedProminent)
            } else {
                ProgressView()
            }
        }
        .padding(30)
        .frame(width: 300, height: 220)
        .onAppear(perform: verify)
    }

    private func verify() {
        Task {
            do {
                // Authenticates the user AND returns a context that can unlock the
                // user-presence-protected passkey item without a second prompt.
                let context = try await KeychainService.shared.passkeyAuthContext(reason: reason)
                await MainActor.run { onVerified(context) }
            } catch {
                // Fail closed with a clear message (and a Cancel button) — never silently
                // fall back to an unauthenticated read.
                await MainActor.run { errorText = error.localizedDescription }
            }
        }
    }
}
