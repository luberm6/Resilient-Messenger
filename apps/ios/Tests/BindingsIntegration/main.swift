import Foundation

func member(_ seed: UInt8) -> FfiMemberCredential {
    FfiMemberCredential(
        deviceId: Data(repeating: seed, count: 16),
        accountId: Data(repeating: seed, count: 32),
        certificateFingerprint: Data(repeating: seed, count: 16)
    )
}

let alice = try MlsDevice.initializeCryptoStore(
    member: member(1),
    stateKey: Data(repeating: 1, count: 32)
)
let bob = try MlsDevice.initializeCryptoStore(
    member: member(2),
    stateKey: Data(repeating: 2, count: 32)
)
let group = Data("swift-uniffi-real-mls".utf8)
let keyPackage = try bob.generateKeyPackages(count: 1)[0]
try alice.createConversation(groupId: group)
let change = try alice.commitAddMember(groupId: group, keyPackage: keyPackage)
_ = try bob.joinConversationFromWelcome(welcome: change[1])
let clear = Data("Swift called real OpenMLS".utf8)
let encrypted = try alice.encryptApplicationMessage(groupId: group, plaintext: clear)
let decrypted = try bob.processIncomingMessage(groupId: group, ciphertext: encrypted)
precondition(decrypted == clear)

let ping = Data([
    0x86, 0x01, 0x01, 0x0e, 0x50, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x00, 0x40,
])
precondition(try protocolRoundTrip(frame: ping) == ping)
print("Swift UniFFI integration: real OpenMLS and canonical CBOR passed")
