import Testing
@testable import ResilientMessengerApp

@Test func protocolVersionIsPinned() {
    #expect(ResilientMessengerFoundation.protocolVersion == 1)
}
