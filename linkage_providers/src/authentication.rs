use crate::error::ProviderResult;
use crate::error::ProviderError;

#[derive(PartialEq, )]
pub enum AuthenticationResult {
    Success,
    Failed,
}

pub trait Authentication {
    type Session;

    fn get_session(&self) -> Option<Self::Session>;

    fn auth_user_password(&self, username: String, password: String) -> ProviderResult<AuthenticationResult> {
        Err(ProviderError::AuthenticationMethodNotImplemented)
    }

    fn auth_id(&self, id: String) -> ProviderResult<AuthenticationResult> {
        Err(ProviderError::AuthenticationMethodNotImplemented)
    }
}