package org.resilient.bindings

import uniffi.messenger_uniffi.FfiMemberCredential
import uniffi.messenger_uniffi.MlsDevice
import uniffi.messenger_uniffi.protocolRoundTrip

private fun member(seed: Byte) = FfiMemberCredential(
    ByteArray(16) { seed },
    ByteArray(32) { seed },
    ByteArray(16) { seed },
)

fun main() {
    val alice = MlsDevice.initializeCryptoStore(member(1), ByteArray(32) { 1 })
    val bob = MlsDevice.initializeCryptoStore(member(2), ByteArray(32) { 2 })
    val group = "kotlin-uniffi-real-mls".encodeToByteArray()
    val keyPackage = bob.generateKeyPackages(1u).single()
    alice.createConversation(group)
    val change = alice.commitAddMember(group, keyPackage)
    bob.joinConversationFromWelcome(change[1])
    val clear = "Kotlin called real OpenMLS".encodeToByteArray()
    val encrypted = alice.encryptApplicationMessage(group, clear)
    check(bob.processIncomingMessage(group, encrypted).contentEquals(clear))

    val ping = "8601010e50070707070707070707070707070707070040"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    check(protocolRoundTrip(ping).contentEquals(ping))
    println("Kotlin UniFFI integration: real OpenMLS and canonical CBOR passed")
}
