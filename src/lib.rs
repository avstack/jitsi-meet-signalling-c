use std::{
  ffi::{c_void, CStr, CString},
  fs::File,
  io::Cursor,
  os::raw::c_char,
  ptr,
  sync::{
    atomic::{AtomicPtr, Ordering},
    Arc,
  },
};

pub use jitsi_meet_signalling::{
  Authentication, ColibriMessage, Conference, Connection, Participant, SessionDescription,
};
use tokio::runtime::Runtime;
use tracing::error;

pub struct Context {
  runtime: Runtime,
}

#[repr(C)]
pub struct Agent {
  opaque: AtomicPtr<c_void>,

  participant_joined: Option<extern "C" fn(*mut c_void, *mut Participant)>,
  participant_left: Option<extern "C" fn(*mut c_void, *mut Participant)>,
  colibri_message_received: Option<extern "C" fn(*mut c_void, *mut ColibriMessage)>,
  offer_received: Option<extern "C" fn(*mut c_void, *const c_char, bool)>,
  source_added: Option<extern "C" fn(*mut c_void, *const c_char)>,
  session_terminate: Option<extern "C" fn(*mut c_void)>,
}

#[async_trait::async_trait]
impl jitsi_meet_signalling::Agent for Agent {
  async fn participant_joined(
    &self,
    conference: Conference,
    participant: Participant,
  ) -> anyhow::Result<()> {
    if let Some(f) = &self.participant_joined {
      f(
        self.opaque.load(Ordering::Relaxed),
        Box::into_raw(Box::new(participant)),
      );
    }
    Ok(())
  }

  async fn participant_left(
    &self,
    conference: Conference,
    participant: Participant,
  ) -> anyhow::Result<()> {
    if let Some(f) = &self.participant_left {
      f(
        self.opaque.load(Ordering::Relaxed),
        Box::into_raw(Box::new(participant)),
      );
    }
    Ok(())
  }

  async fn colibri_message_received(
    &self,
    conference: Conference,
    message: ColibriMessage,
  ) -> anyhow::Result<()> {
    if let Some(f) = &self.colibri_message_received {
      f(
        self.opaque.load(Ordering::Relaxed),
        Box::into_raw(Box::new(message)),
      );
    }
    Ok(())
  }

  async fn offer_received(
    &self,
    conference: Conference,
    offer: SessionDescription,
    should_send_answer: bool,
  ) -> anyhow::Result<()> {
    if let Some(f) = &self.offer_received {
      let offer = CString::new(offer.marshal()).unwrap();
      f(
        self.opaque.load(Ordering::Relaxed),
        offer.as_ptr(),
        should_send_answer,
      );
    }
    Ok(())
  }

  async fn session_terminate(&self, conference: Conference) -> anyhow::Result<()> {
    if let Some(f) = &self.session_terminate {
      f(self.opaque.load(Ordering::Relaxed));
    }
    Ok(())
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_logging_init_stdout(level: *const c_char) -> bool {
  assert!(!level.is_null());
  if let Ok(level) = CStr::from_ptr(level).to_str() {
    if let Ok(level) = level.parse::<tracing::Level>() {
      tracing_subscriber::fmt().with_max_level(level).init();
      true
    }
    else {
      false
    }
  }
  else {
    false
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_logging_init_file(
  path: *const c_char,
  level: *const c_char,
) -> bool {
  assert!(!path.is_null());
  assert!(!level.is_null());
  if let Ok(path) = CStr::from_ptr(path).to_str() {
    if let Ok(level) = CStr::from_ptr(level).to_str() {
      if let Ok(level) = level.parse::<tracing::Level>() {
        if let Ok(file) = File::create(path) {
          tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(file)
            .init();
          true
        }
        else {
          false
        }
      }
      else {
        false
      }
    }
    else {
      false
    }
  }
  else {
    false
  }
}

#[no_mangle]
pub extern "C" fn jitsi_context_create() -> *mut Context {
  Box::into_raw(Box::new(Context {
    runtime: Runtime::new().unwrap(),
  }))
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_context_free(context: *mut Context) {
  assert!(!context.is_null());
  drop(Box::from_raw(context));
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_connection_connect(
  context: *mut Context,
  websocket_url: *const c_char,
  xmpp_domain: *const c_char,
  tls_insecure: bool,
) -> *mut Connection {
  assert!(!context.is_null());
  assert!(!websocket_url.is_null());
  assert!(!xmpp_domain.is_null());
  let connection = (*context)
    .runtime
    .block_on(Connection::connect(
      CStr::from_ptr(websocket_url).to_str().unwrap(),
      CStr::from_ptr(xmpp_domain).to_str().unwrap(),
      Authentication::Anonymous,
      tls_insecure,
    ))
    .unwrap();
  Box::into_raw(Box::new(connection))
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_connection_free(connection: *mut Connection) {
  assert!(!connection.is_null());
  drop(Box::from_raw(connection));
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_connection_join(
  context: *mut Context,
  connection: *mut Connection,
  conference_name: *const c_char,
  nick: *const c_char,
  agent: Agent,
) -> *mut Conference {
  assert!(!context.is_null());
  assert!(!connection.is_null());
  assert!(!conference_name.is_null());
  assert!(!nick.is_null());
  let conference = (*context)
    .runtime
    .block_on((*connection).join(
      CStr::from_ptr(conference_name).to_str().unwrap(),
      CStr::from_ptr(nick).to_str().unwrap(),
      Arc::new(agent),
    ))
    .unwrap();
  Box::into_raw(Box::new(conference))
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_accept(
  context: *mut Context,
  conference: *mut Conference,
  session_description: *const c_char,
) {
  assert!(!context.is_null());
  assert!(!conference.is_null());
  assert!(!session_description.is_null());
  let session_description = CStr::from_ptr(session_description).to_str().unwrap();
  match SessionDescription::unmarshal(&mut Cursor::new(session_description)) {
    Ok(session_description) => match (*context)
      .runtime
      .block_on((*conference).accept(session_description))
    {
      Ok(_) => {},
      Err(e) => error!(
        "jitsi_conference_accept: error handling session description: {}",
        e
      ),
    },
    Err(e) => error!(
      "jitsi_conference_accept: failed to unmarshal session description: {}",
      e
    ),
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_local_endpoint_id(
  conference: *mut Conference,
) -> *mut c_char {
  assert!(!conference.is_null());
  (*conference)
    .endpoint_id()
    .map(|endpoint_id| CString::new(endpoint_id.to_string()).unwrap().into_raw())
    .unwrap_or_else(|_| ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_participant(
  context: *mut Context,
  conference: *mut Conference,
  endpoint_id: *const c_char,
) -> *mut Participant {
  assert!(!context.is_null());
  assert!(!conference.is_null());
  assert!(!endpoint_id.is_null());
  let endpoint_id = CStr::from_ptr(endpoint_id).to_str().unwrap();
  (*context)
    .runtime
    .block_on((*conference).participant(endpoint_id))
    .map(|participant| Box::into_raw(Box::new(participant)))
    .unwrap_or_else(|| ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_free(conference: *mut Conference) {
  assert!(!conference.is_null());
  drop(Box::from_raw(conference));
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_jid(participant: *mut Participant) -> *mut c_char {
  assert!(!participant.is_null());
  (*participant)
    .jid
    .as_ref()
    .map(|jid| CString::new(jid.to_string()).unwrap().into_raw())
    .unwrap_or_else(ptr::null_mut)
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_endpoint_id(
  participant: *mut Participant,
) -> *mut c_char {
  assert!(!participant.is_null());
  (*participant)
    .endpoint_id()
    .map(|endpoint_id| CString::new(endpoint_id.to_string()).unwrap().into_raw())
    .unwrap_or_else(|_| ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_nick(participant: *mut Participant) -> *mut c_char {
  assert!(!participant.is_null());
  (*participant)
    .nick
    .as_ref()
    .map(|nick| CString::new(nick.clone()).unwrap().into_raw())
    .unwrap_or_else(ptr::null_mut)
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_free(participant: *mut Participant) {
  assert!(!participant.is_null());
  drop(Box::from_raw(participant));
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_string_free(s: *mut c_char) {
  assert!(!s.is_null());
  drop(CString::from_raw(s));
}
