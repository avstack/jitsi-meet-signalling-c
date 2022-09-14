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
  unsafe fn inner(level: *const c_char) -> anyhow::Result<()> {
    let level: tracing::Level = CStr::from_ptr(level).to_str()?.parse()?;
    tracing_subscriber::fmt().with_max_level(level).init();
    Ok(())
  }

  if level.is_null() {
    return false;
  }

  match inner(level) {
    Ok(_) => true,
    Err(e) => {
      error!("Failed to set up logging: {}", e);
      false
    },
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_logging_init_file(
  path: *const c_char,
  level: *const c_char,
) -> bool {
  unsafe fn inner(path: *const c_char, level: *const c_char) -> anyhow::Result<()> {
    let path = CStr::from_ptr(path).to_str()?;
    let level: tracing::Level = CStr::from_ptr(level).to_str()?.parse()?;
    let file = File::create(path)?;
    tracing_subscriber::fmt()
      .with_max_level(level)
      .with_writer(file)
      .init();
    Ok(())
  }

  if path.is_null() || level.is_null() {
    return false;
  }

  match inner(path, level) {
    Ok(_) => true,
    Err(e) => {
      error!("Failed to set up logging: {}", e);
      false
    },
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
  if !context.is_null() {
    drop(Box::from_raw(context));
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_connection_connect(
  context: *mut Context,
  websocket_url: *const c_char,
  xmpp_domain: *const c_char,
  tls_insecure: bool,
) -> *mut Connection {
  if context.is_null() || websocket_url.is_null() || xmpp_domain.is_null() {
    return ptr::null_mut();
  }

  let websocket_url = match CStr::from_ptr(websocket_url).to_str() {
    Ok(url) => url,
    Err(e) => {
      error!("Invalid websocket_url: {}", e);
      return ptr::null_mut();
    },
  };

  let xmpp_domain = match CStr::from_ptr(xmpp_domain).to_str() {
    Ok(url) => url,
    Err(e) => {
      error!("Invalid xmpp_domain: {}", e);
      return ptr::null_mut();
    },
  };

  let result = (*context).runtime.block_on(Connection::connect(
    websocket_url,
    xmpp_domain,
    Authentication::Anonymous,
    tls_insecure,
  ));

  match result {
    Ok(connection) => Box::into_raw(Box::new(connection)),
    Err(e) => {
      error!("Failed to connect: {}", e);
      ptr::null_mut()
    },
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_connection_free(connection: *mut Connection) {
  if !connection.is_null() {
    drop(Box::from_raw(connection));
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_connection_join(
  context: *mut Context,
  connection: *mut Connection,
  conference_name: *const c_char,
  nick: *const c_char,
  agent: Agent,
) -> *mut Conference {
  if context.is_null() || connection.is_null() || conference_name.is_null() || nick.is_null() {
    return ptr::null_mut();
  }

  let conference_name = match CStr::from_ptr(conference_name).to_str() {
    Ok(name) => name,
    Err(e) => {
      error!("Invalid conference_name: {}", e);
      return ptr::null_mut();
    },
  };

  let nick = match CStr::from_ptr(nick).to_str() {
    Ok(nick) => nick,
    Err(e) => {
      error!("Invalid nick: {}", e);
      return ptr::null_mut();
    },
  };

  let result =
    (*context)
      .runtime
      .block_on((*connection).join(conference_name, nick, Arc::new(agent)));

  match result {
    Ok(conference) => Box::into_raw(Box::new(conference)),
    Err(e) => {
      error!("Failed to join: {}", e);
      ptr::null_mut()
    },
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_accept(
  context: *mut Context,
  conference: *mut Conference,
  session_description: *const c_char,
) {
  if context.is_null() || conference.is_null() || session_description.is_null() {
    return;
  }

  let session_description = match CStr::from_ptr(session_description).to_str() {
    Ok(sd) => sd,
    Err(e) => {
      error!("Invalid session_description: {}", e);
      return;
    },
  };

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
  if !conference.is_null() {
    (*conference)
      .endpoint_id()
      .map(|endpoint_id| CString::new(endpoint_id.to_string()).unwrap().into_raw())
      .unwrap_or_else(|_| ptr::null_mut())
  }
  else {
    ptr::null_mut()
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_participant(
  context: *mut Context,
  conference: *mut Conference,
  endpoint_id: *const c_char,
) -> *mut Participant {
  if context.is_null() || conference.is_null() || endpoint_id.is_null() {
    return ptr::null_mut();
  }

  let endpoint_id = match CStr::from_ptr(endpoint_id).to_str() {
    Ok(id) => id,
    Err(e) => {
      error!("Invalid endpoint_id: {}", e);
      return ptr::null_mut();
    },
  };

  (*context)
    .runtime
    .block_on((*conference).participant(endpoint_id))
    .map(|participant| Box::into_raw(Box::new(participant)))
    .unwrap_or_else(ptr::null_mut)
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_conference_free(conference: *mut Conference) {
  if !conference.is_null() {
    drop(Box::from_raw(conference));
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_jid(participant: *mut Participant) -> *mut c_char {
  if !participant.is_null() {
    (*participant)
      .jid
      .as_ref()
      .map(|jid| CString::new(jid.to_string()).unwrap().into_raw())
      .unwrap_or_else(ptr::null_mut)
  }
  else {
    ptr::null_mut()
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_endpoint_id(
  participant: *mut Participant,
) -> *mut c_char {
  if !participant.is_null() {
    (*participant)
      .endpoint_id()
      .map(|endpoint_id| CString::new(endpoint_id.to_string()).unwrap().into_raw())
      .unwrap_or_else(|_| ptr::null_mut())
  }
  else {
    ptr::null_mut()
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_nick(participant: *mut Participant) -> *mut c_char {
  if !participant.is_null() {
    (*participant)
      .nick
      .as_ref()
      .map(|nick| CString::new(nick.clone()).unwrap().into_raw())
      .unwrap_or_else(ptr::null_mut)
  }
  else {
    ptr::null_mut()
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_participant_free(participant: *mut Participant) {
  if !participant.is_null() {
    drop(Box::from_raw(participant));
  }
}

#[no_mangle]
pub unsafe extern "C" fn jitsi_string_free(s: *mut c_char) {
  if !s.is_null() {
    drop(CString::from_raw(s));
  }
}
