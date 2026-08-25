#![forbid(unsafe_code)]
//! Compact v1 protocol. The wire format is a restricted, canonical RFC 8949 CBOR profile.
//! It accepts only definite-length arrays, unsigned integers and byte strings; maps,
//! tags, floats and indefinite forms are rejected before an application can parse them.

use std::fmt;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
pub const MAX_ENCRYPTED_TEXT_EVENT_SIZE: usize = 4 * 1024;
pub const MAX_BATCH_SIZE: usize = 50;
pub const DEFAULT_TTL_SECONDS: u32 = 7 * 24 * 60 * 60;
pub const SIZE_WARNING_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Id(pub [u8; 16]);
pub type AccountId = Id;
pub type DeviceId = Id;
pub type ConversationId = Id;
pub type EventId = Id;
pub type ClientMessageId = Id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 1, ServerHello, AuthChallenge, AuthResponse, AuthAccepted,
    UploadEnvelope, UploadAccepted, SyncRequest, SyncBatch, DeliveryReceiptBatch,
    ReadReceiptBatch, RelayDirectoryRequest, RelayDirectoryResponse, Ping, Pong,
    RateLimit, Error,
}
impl FrameType { fn parse(n: u64) -> Result<Self, Error> { match n {
    1=>Ok(Self::ClientHello),2=>Ok(Self::ServerHello),3=>Ok(Self::AuthChallenge),4=>Ok(Self::AuthResponse),5=>Ok(Self::AuthAccepted),6=>Ok(Self::UploadEnvelope),7=>Ok(Self::UploadAccepted),8=>Ok(Self::SyncRequest),9=>Ok(Self::SyncBatch),10=>Ok(Self::DeliveryReceiptBatch),11=>Ok(Self::ReadReceiptBatch),12=>Ok(Self::RelayDirectoryRequest),13=>Ok(Self::RelayDirectoryResponse),14=>Ok(Self::Ping),15=>Ok(Self::Pong),16=>Ok(Self::RateLimit),17=>Ok(Self::Error), _=>Err(Error::UnknownFrameType) } } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApplicationType {
    TextMessage = 1, MessageRequest, MessageRequestAccepted, DeliveryReceipt,
    ReadReceipt, GroupMetadataUpdate, GroupMemberEvent, GroupInvite,
    GroupInviteAccepted, DeviceLinked, DeviceRemoved,
}
impl ApplicationType { fn parse(n:u64)->Result<Self,Error>{match n {1=>Ok(Self::TextMessage),2=>Ok(Self::MessageRequest),3=>Ok(Self::MessageRequestAccepted),4=>Ok(Self::DeliveryReceipt),5=>Ok(Self::ReadReceipt),6=>Ok(Self::GroupMetadataUpdate),7=>Ok(Self::GroupMemberEvent),8=>Ok(Self::GroupInvite),9=>Ok(Self::GroupInviteAccepted),10=>Ok(Self::DeviceLinked),11=>Ok(Self::DeviceRemoved),_=>Err(Error::UnknownApplicationType)}} }

/// The opaque `body` is ciphertext or control data. It never carries identities, contact
/// details, titles or message previews in the transport envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportFrame { pub version: u16, pub kind: FrameType, pub client_message_id: ClientMessageId, pub ttl_seconds: u32, pub body: Vec<u8> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationEnvelope { pub kind: ApplicationType, pub event_id: EventId, pub conversation_id: ConversationId, pub encrypted_content: Vec<u8> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode { Malformed=1, UnsupportedVersion=2, TooLarge=3, Replay=4, Duplicate=5, RateLimited=6, CursorRegression=7 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error { Malformed, Truncated, TooLarge, NonCanonical, UnsupportedVersion, UnknownFrameType, UnknownApplicationType, TrailingBytes, FieldOutOfRange }
impl fmt::Display for Error { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"{self:?}") } }
impl std::error::Error for Error {}

/// Compression policy hook for a negotiated compressor. `compressed_body` must include
/// its own compression framing; only a strictly smaller complete body is selected.
pub fn choose_compressed_body(original: &[u8], compressed_body: &[u8]) -> Option<Vec<u8>> {
    (compressed_body.len() < original.len()).then(|| compressed_body.to_vec())
}

impl TransportFrame {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.body.len() > MAX_FRAME_SIZE { return Err(Error::TooLarge); }
        let mut e=Encoder::new(); e.array(6); e.uint(1); e.uint(self.version as u64); e.uint(self.kind as u64); e.bytes(&self.client_message_id.0); e.uint(self.ttl_seconds as u64); e.bytes(&self.body);
        let out=e.finish(); if out.len()>MAX_FRAME_SIZE {Err(Error::TooLarge)} else {Ok(out)}
    }
    pub fn decode(input:&[u8])->Result<Self,Error>{
        if input.len()>MAX_FRAME_SIZE{return Err(Error::TooLarge)} let mut d=Decoder::new(input); d.array_len(6)?; if d.uint()?!=1{return Err(Error::Malformed)} let version=d.uint()?; if version!=PROTOCOL_VERSION as u64{return Err(Error::UnsupportedVersion)} let kind=FrameType::parse(d.uint()?)?; let id=d.id()?; let ttl=d.uint()?; if ttl>u32::MAX as u64{return Err(Error::FieldOutOfRange)} let body=d.bytes()?.to_vec(); d.finish()?; Ok(Self{version:version as u16,kind,client_message_id:id,ttl_seconds:ttl as u32,body})
    }
}
impl ApplicationEnvelope {
    pub fn encode(&self)->Result<Vec<u8>,Error>{ if self.encrypted_content.len()>MAX_ENCRYPTED_TEXT_EVENT_SIZE{return Err(Error::TooLarge)} let mut e=Encoder::new(); e.array(5);e.uint(2);e.uint(self.kind as u64);e.bytes(&self.event_id.0);e.bytes(&self.conversation_id.0);e.bytes(&self.encrypted_content);Ok(e.finish()) }
    pub fn decode(input:&[u8])->Result<Self,Error>{let mut d=Decoder::new(input);d.array_len(5)?;if d.uint()?!=2{return Err(Error::Malformed)}let kind=ApplicationType::parse(d.uint()?)?;let event_id=d.id()?;let conversation_id=d.id()?;let encrypted_content=d.bytes()?.to_vec();if encrypted_content.len()>MAX_ENCRYPTED_TEXT_EVENT_SIZE{return Err(Error::TooLarge)}d.finish()?;Ok(Self{kind,event_id,conversation_id,encrypted_content})}
}

struct Encoder(Vec<u8>); impl Encoder { fn new()->Self{Self(Vec::new())} fn finish(self)->Vec<u8>{self.0} fn array(&mut self,n:usize){self.major(4,n as u64)} fn uint(&mut self,n:u64){self.major(0,n)} fn bytes(&mut self,b:&[u8]){self.major(2,b.len() as u64);self.0.extend_from_slice(b)} fn major(&mut self,m:u8,n:u64){if n<24{self.0.push((m<<5)|n as u8)}else if n<=u8::MAX as u64{self.0.extend_from_slice(&[(m<<5)|24,n as u8])}else if n<=u16::MAX as u64{self.0.push((m<<5)|25);self.0.extend_from_slice(&(n as u16).to_be_bytes())}else{self.0.push((m<<5)|26);self.0.extend_from_slice(&(n as u32).to_be_bytes())}} }
struct Decoder<'a>{b:&'a[u8],p:usize} impl<'a> Decoder<'a>{fn new(b:&'a[u8])->Self{Self{b,p:0}} fn head(&mut self)->Result<(u8,u64),Error>{let x=*self.b.get(self.p).ok_or(Error::Truncated)?;self.p+=1;let m=x>>5;let a=x&31;let n=match a{0..=23=>a as u64,24=>self.take(1)?[0] as u64,25=>u16::from_be_bytes(self.take(2)?.try_into().map_err(|_|Error::Truncated)?)as u64,26=>u32::from_be_bytes(self.take(4)?.try_into().map_err(|_|Error::Truncated)?)as u64,_=>return Err(Error::NonCanonical)};if (a==24&&n<24)||(a==25&&n<=u8::MAX as u64)||(a==26&&n<=u16::MAX as u64){return Err(Error::NonCanonical)}Ok((m,n))} fn take(&mut self,n:usize)->Result<&'a[u8],Error>{let end=self.p.checked_add(n).ok_or(Error::Truncated)?;let r=self.b.get(self.p..end).ok_or(Error::Truncated)?;self.p=end;Ok(r)}fn uint(&mut self)->Result<u64,Error>{let(m,n)=self.head()?;if m==0{Ok(n)}else{Err(Error::Malformed)}}fn array_len(&mut self,n:usize)->Result<(),Error>{let(m,x)=self.head()?;if m==4&&x==n as u64{Ok(())}else{Err(Error::Malformed)}}fn bytes(&mut self)->Result<&'a[u8],Error>{let(m,n)=self.head()?;if m!=2{return Err(Error::Malformed)}self.take(n as usize)}fn id(&mut self)->Result<Id,Error>{let b=self.bytes()?;if b.len()!=16{return Err(Error::FieldOutOfRange)}let mut x=[0;16];x.copy_from_slice(b);Ok(Id(x))}fn finish(self)->Result<(),Error>{if self.p==self.b.len(){Ok(())}else{Err(Error::TrailingBytes)}}}

#[cfg(test)] mod tests { use super::*; fn id()->Id{Id([7;16])} fn frame()->TransportFrame{TransportFrame{version:1,kind:FrameType::Ping,client_message_id:id(),ttl_seconds:0,body:vec![]}} #[test]fn deterministic_round_trip(){let a=frame().encode().unwrap();assert_eq!(a,frame().encode().unwrap());assert_eq!(TransportFrame::decode(&a).unwrap(),frame());assert_eq!(hex(&a),"8601010e50070707070707070707070707070707070040")} #[test]fn rejects_malformed_truncated_oversized_and_map(){assert!(matches!(TransportFrame::decode(&[0x86]),Err(Error::Truncated)));assert!(matches!(TransportFrame::decode(&[0xa1,0,0]),Err(Error::Malformed)));assert!(matches!(TransportFrame::decode(&vec![0;MAX_FRAME_SIZE+1]),Err(Error::TooLarge)))} #[test]fn app_round_trip(){let x=ApplicationEnvelope{kind:ApplicationType::TextMessage,event_id:id(),conversation_id:id(),encrypted_content:vec![1,2]};assert_eq!(ApplicationEnvelope::decode(&x.encode().unwrap()).unwrap(),x)} #[test]fn compression_requires_real_saving(){assert!(choose_compressed_body(&[1,2],&[1,2]).is_none());assert_eq!(choose_compressed_body(&[1,2,3],&[9]),Some(vec![9]))} #[test]fn fuzz_corpus_never_panics(){let mut x=1u64;for _ in 0..5000{x=x.wrapping_mul(6364136223846793005).wrapping_add(1);let n=(x as usize)%80;let mut v=vec![0;n];for b in &mut v{x=x.wrapping_mul(2862933555777941757).wrapping_add(1);*b=x as u8}let _=TransportFrame::decode(&v)}} fn hex(b:&[u8])->String{b.iter().map(|x|format!("{x:02x}")).collect()} }
