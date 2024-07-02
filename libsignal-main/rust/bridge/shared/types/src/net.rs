//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::panic::RefUnwindSafe;

use http::uri::PathAndQuery;
use libsignal_net::auth::Auth;
use libsignal_net::enclave::{
    Cdsi, EnclaveEndpoint, EnclaveEndpointConnection, EnclaveKind, Nitro, PpssSetup, Sgx, Tpm2Snp,
};
use libsignal_net::env;
use libsignal_net::env::{add_user_agent_header, Env, Svr3Env};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::{
    DirectConnector as TcpSslDirectConnector, ProxyConnector as TcpSslProxyConnector,
    TcpSslConnector, TcpSslConnectorStream,
};
use libsignal_net::infra::{make_ws_config, EndpointConnection};
use libsignal_net::svr::{self, SvrConnection};
use libsignal_net::timeouts::ONE_ROUTE_CONNECTION_TIMEOUT;

use crate::*;

pub mod cdsi;
pub mod chat;
pub mod tokio;

pub use tokio::TokioAsyncContext;

#[derive(num_enum::TryFromPrimitive)]
#[repr(u8)]
#[derive(Clone, Copy, strum::Display)]
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    fn env<'a>(self) -> Env<'a, Svr3Env<'a>> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }
}

pub struct ConnectionManager {
    chat: EndpointConnection<MultiRouteConnectionManager>,
    cdsi: EnclaveEndpointConnection<Cdsi, MultiRouteConnectionManager>,
    svr3: (
        EnclaveEndpointConnection<Sgx, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Nitro, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Tpm2Snp, MultiRouteConnectionManager>,
    ),
    transport_connector: std::sync::Mutex<TcpSslConnector>,
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    pub fn new(environment: Environment, user_agent: String) -> Self {
        log::info!("Initializing connection manager for {}...", &environment);
        let dns_resolver =
            DnsResolver::new_with_static_fallback(environment.env().static_fallback());
        let transport_connector =
            std::sync::Mutex::new(TcpSslDirectConnector::new(dns_resolver).into());
        let chat_endpoint = PathAndQuery::from_static(env::constants::WEB_SOCKET_PATH);
        let chat_connection_params = environment
            .env()
            .chat_domain_config
            .connection_params_with_fallback();
        let chat_connection_params = add_user_agent_header(chat_connection_params, &user_agent);
        let chat_ws_config = make_ws_config(chat_endpoint, ONE_ROUTE_CONNECTION_TIMEOUT);
        Self {
            chat: EndpointConnection::new_multi(
                chat_connection_params,
                ONE_ROUTE_CONNECTION_TIMEOUT,
                chat_ws_config,
            ),
            cdsi: Self::endpoint_connection(&environment.env().cdsi, &user_agent),
            svr3: (
                Self::endpoint_connection(environment.env().svr3.sgx(), &user_agent),
                Self::endpoint_connection(environment.env().svr3.nitro(), &user_agent),
                Self::endpoint_connection(environment.env().svr3.tpm2snp(), &user_agent),
            ),
            transport_connector,
        }
    }

    pub fn set_proxy(&self, host: &str, port: Option<NonZeroU16>) -> Result<(), std::io::Error> {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        // We take port as an i32 because Java 'short' is signed and thus can't represent all port
        // numbers, and we want too-large port numbers to be handled the same way as 0.
        match port {
            Some(port) => {
                let proxy_addr = (host, port);
                match &mut *guard {
                    TcpSslConnector::Direct(direct) => {
                        *guard = direct.with_proxy(proxy_addr).into()
                    }
                    TcpSslConnector::Proxied(proxied) => proxied.set_proxy(proxy_addr),
                    TcpSslConnector::Invalid(dns_resolver) => {
                        *guard = TcpSslProxyConnector::new(dns_resolver.clone(), proxy_addr).into()
                    }
                };
                Ok(())
            }
            None => {
                match &*guard {
                    TcpSslConnector::Direct(TcpSslDirectConnector { dns_resolver, .. })
                    | TcpSslConnector::Proxied(TcpSslProxyConnector { dns_resolver, .. }) => {
                        *guard = TcpSslConnector::Invalid(dns_resolver.clone())
                    }
                    TcpSslConnector::Invalid(_dns_resolver) => (),
                }
                Err(std::io::ErrorKind::InvalidInput.into())
            }
        }
    }

    pub fn clear_proxy(&self) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        match &*guard {
            TcpSslConnector::Direct(_direct) => (),
            TcpSslConnector::Proxied(TcpSslProxyConnector { dns_resolver, .. })
            | TcpSslConnector::Invalid(dns_resolver) => {
                *guard = TcpSslDirectConnector::new(dns_resolver.clone()).into()
            }
        };
    }

    pub fn set_ipv6_enabled(&self, ipv6_enabled: bool) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_ipv6_enabled(ipv6_enabled);
    }

    fn endpoint_connection<E: EnclaveKind>(
        endpoint: &EnclaveEndpoint<'static, E>,
        user_agent: &str,
    ) -> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
        let params = endpoint.domain_config.connection_params_with_fallback();
        let params = add_user_agent_header(params, user_agent);
        EnclaveEndpointConnection::new_multi(endpoint, params, ONE_ROUTE_CONNECTION_TIMEOUT)
    }
}

bridge_as_handle!(ConnectionManager);

pub async fn svr3_connect<'a>(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<<Svr3Env<'a> as PpssSetup<TcpSslConnectorStream>>::Connections, svr::Error> {
    let auth = Auth { username, password };
    let ConnectionManager {
        chat: _chat,
        cdsi: _cdsi,
        svr3: (sgx, nitro, tpm2snp),
        transport_connector,
    } = connection_manager;
    let transport_connector = transport_connector.lock().expect("not poisoned").clone();
    let sgx = SvrConnection::connect(auth.clone(), sgx, transport_connector.clone()).await?;
    let nitro = SvrConnection::connect(auth.clone(), nitro, transport_connector.clone()).await?;
    let tpm2snp = SvrConnection::connect(auth, tpm2snp, transport_connector).await?;
    Ok((sgx, nitro, tpm2snp))
}

#[cfg(test)]
mod test {
    use super::*;
    use test_case::test_case;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env, "test-user-agent".to_string());
    }
}
