// SPDX-License-Identifier: Apache-2.0

extern crate serde_derive;

use ::host_components::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::Filter;

#[tokio::main]
async fn main() {
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), BIND_PORT);

    //find available backends for this host (currently only local - may extend?)
    let available_backends = models::populate_available_backends();

    //Provide mechanism to find existing Keeps
    let keeploaderlist = models::find_existing_keep_loaders();

    let declare = warp::any().map(|| {
        format!(
            "Protocol_name = {}\nProtocol_version = {}",
            PROTO_NAME, PROTO_VERSION
        )
    });

    let keep_posts = warp::post()
        .and(warp::path("keeps_post"))
        .and(warp::body::json())
        .and(filters::with_available_backends(available_backends.await))
        .and(filters::with_keeploaderlist(keeploaderlist.await))
        .and_then(filters::keeps_parse);

    let routes = keep_posts.or(declare);
    println!(
        "Starting server on {}, {} v{}",
        BIND_PORT, PROTO_NAME, PROTO_VERSION
    );
    warp::serve(routes)
        .tls()
        .cert_path("key-material/server.crt")
        .key_path("key-material/server.key")
        .run(socket)
        .await;
}

mod models {
    use ::host_components::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub async fn populate_available_backends() -> Vec<String> {
        let mut available_backends = Vec::new();
        //add backends - assume both KVM and Wasi ("nil") are available
        //TODO - add checks for SEV and SGX
        available_backends.push(KEEP_ARCH_NIL.to_string());
        available_backends.push(KEEP_ARCH_KVM.to_string());
        available_backends.clone()
    }

    pub fn new_empty_keeploaderlist() -> KeepLoaderList {
        Arc::new(Mutex::new(Vec::new()))
    }
    pub async fn find_existing_keep_loaders() -> KeepLoaderList {
        println!("Looking for existing keep-loaders in /tmp");
        let kllvec = new_empty_keeploaderlist();
        //TODO - implement (scheme required)
        kllvec
    }
}

mod filters {
    use ::host_components::*;
    use std::collections::{HashMap, HashSet};
    use std::convert::Infallible;
    use std::io::prelude::*;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use uuid::Uuid;
    use warp::Filter;

    pub fn with_available_backends(
        available_backends: Vec<String>,
    ) -> impl Filter<Extract = (Vec<String>,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || available_backends.clone())
    }

    pub fn with_keeploaderlist(
        keeploaderlist: KeepLoaderList,
    ) -> impl Filter<Extract = (KeepLoaderList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || keeploaderlist.clone())
    }

    pub fn new_keep(
        authtoken: &str,
        apploaderbindport: u16,
        _apploaderbindaddr: &str,
        backend: &str,
    ) -> KeepLoader {
        let new_kuuid = Uuid::new_v4();
        //TODO - create UNIX socket
        let bind_socket = format!("/tmp/enarx-keep-{}.sock", &kuuid);
        //FIXME - change to listen?
        let mut stream = UnixStream::connect(bind_socket).expect("failed to connect");

        println!("Received auth_token {}", authtoken);
        println!("About to spawn new keep-loader");
        //TODO - remove hard-coded systemd-escape sequence ("\x20")
        let operation_type = "exec";
        let service_cmd = format!("enarx-keep@{}\\x20{}.service", operation_type, new_kuuid);
        //let service_cmd = format!("enarx-keep@\"{}\\x20{}\".service", operation_type, new_kuuid);
        println!("service_cmd = {}", service_cmd);
        let _child = Command::new("systemctl")
            .arg("--user")
            .arg("start")
            .arg(service_cmd)
            .output()
            .expect("failed to execute child");

        println!("Spawned new keep-loader");
        println!(
            "Got this far with authtoken = {}, new_kuuid = {}, apploaderbindport = {}",
            authtoken, new_kuuid, apploaderbindport
        );

        KeepLoader {
            state: KEEP_LOADER_STATE_UNDEF,
            kuuid: new_kuuid,
            app_loader_bind_port: apploaderbindport,
            bindaddress: "".to_string(),
            unix_socket: stream,
            backend: backend.to_string(),
        }
    }

    pub fn assign_port(kllvec: Vec<KeepLoader>, requestedport: u16) -> u16 {
        let mut assigned_ports: HashSet<u16> = HashSet::new();
        for existing in kllvec.iter() {
            assigned_ports.insert(existing.app_loader_bind_port);
        }
        let chosen_port: u16;
        if !assigned_ports.contains(&requestedport) {
            chosen_port = requestedport;
        } else {
            let mut check_port: u16 = APP_LOADER_BIND_PORT_START;
            for check_add in 0..kllvec.len() {
                check_port = APP_LOADER_BIND_PORT_START + check_add as u16;
                println!("check_port = {}", &check_port);
                if !assigned_ports.contains(&check_port) {
                    break;
                }
                check_port += check_port;
            }
            chosen_port = check_port;
        }
        chosen_port
    }

    pub async fn keeps_parse(
        command_group: HashMap<String, String>,
        available_backends: Vec<String>,
        keeploaderlist: KeepLoaderList,
    ) -> Result<impl warp::Reply, Infallible> {
        let undefined = UndefinedReply {
            text: String::from("undefined"),
        };
        let mut json_reply = warp::reply::json(&undefined);

        match command_group.get(KEEP_COMMAND).unwrap().as_str() {
            "list-keep-types" => {
                //TODO - populate and return
                json_reply = warp::reply::json(&available_backends)
            }
            "new-keep" => {
                //assume unsupported to start
                let mut supported: bool = false;
                println!("new-keep ...");
                let authtoken = command_group.get(KEEP_AUTH).unwrap();
                let keeparch = command_group.get(KEEP_ARCH).unwrap().as_str();
                //               match keeparch {

                if available_backends.iter().any(|backend| backend == keeparch) {
                    supported = true;
                }

                if supported {
                    let mut kll = keeploaderlist.lock().await;
                    let kllvec: Vec<KeepLoader> = kll.clone().into_iter().collect();

                    let new_keeploader = new_keep(authtoken, 0, "", keeparch);
                    println!(
                        "Keeploaderlist currently has {} entries, about to add {}",
                        kll.len(),
                        new_keeploader.kuuid,
                    );
                    //TODO - pass UNIX socket in arguments
                    //TODO - pass backend-type in Environment
                    //TODO - spawn new keepldr
                    //TODO - add keeploader to kllvec
                    //add this new new keeploader to the list
                    kll.push(new_keeploader.clone());
                    json_reply = warp::reply::json(&new_keeploader);
                } else {
                    //FIXME - Error out
                    json_reply = warp::reply::json(&new_keeploader);
                }
            }
            "list-keeps" => {
                //update list
                let kll = keeploaderlist.lock().await;

                let kllvec: Vec<KeepLoader> = kll.clone().into_iter().collect();
                for keeploader in &kllvec {
                    println!(
                        "Keep kuuid {}, state {}, listening on {}:{}",
                        keeploader.kuuid,
                        keeploader.state,
                        keeploader.bindaddress,
                        keeploader.app_loader_bind_port
                    );
                }
                let json_keeploadervec = KeepLoaderVec { klvec: kllvec };
                json_reply = warp::reply::json(&json_keeploadervec);
            }
            /*
            "start-keep" => {
                let mut kll = keeploaderlist.lock().await;
                let kllvec: Vec<KeepLoader> = kll.clone().into_iter().collect();
                let kuuid: Uuid = command_group.get(KEEP_KUUID).unwrap().parse().unwrap();

                let keepaddr_opt = command_group.get(KEEP_ADDR);
                let keepport_opt = command_group.get(KEEP_PORT);
                let ap_bind_addr: &str;
                let ap_bind_port: u16;
                //TODO - need unit tests for this
                match keepaddr_opt {
                    Some(addr) => {
                        println!("start-keep received {}", &addr);
                        ap_bind_addr = addr;
                        //if we have been provided with a port, we use that,
                        // if not, default to default (APP_LOADER_BIND_PORT_START).
                        // ASSERT: we cannot be expected to manage all possible
                        //  IP addresses and associated ports
                        match keepport_opt {
                            Some(port) => {
                                println!("... and port {}", port);
                                match ap_bind_addr {
                                    //deal with the case where we're on localhost, in which case
                                    // we'll auto-assign
                                    "127.0.0.1" => {
                                        ap_bind_port =
                                            assign_port(kllvec, APP_LOADER_BIND_PORT_START)
                                    }
                                    &_ => {
                                        ap_bind_port = port.parse().expect("Problems parsing port")
                                    }
                                }
                            }
                            None => match ap_bind_addr {
                                "127.0.0.1" => {
                                    ap_bind_port = assign_port(kllvec, APP_LOADER_BIND_PORT_START)
                                }
                                &_ => ap_bind_port = APP_LOADER_BIND_PORT_START,
                            },
                        }
                    }
                    //if we have no address, then we use localhost and try suggested
                    // but auto-assign if it's already taken
                    None => {
                        println!("start-keep received no address, so starting on localhost");
                        ap_bind_addr = "127.0.0.1";
                        //request the very first available port
                        // assign_port will grant the next available if
                        // APP_LOADER_BIND_PORT_START is not available
                        ap_bind_port = assign_port(kllvec, APP_LOADER_BIND_PORT_START);
                    }
                }
                let bind_socket = format!("/tmp/enarx-keep-{}.sock", &kuuid);

                //construct commands with the relevant details
                let json_set_app_addr = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_ADDR),
                    commandcontents: ap_bind_addr.to_string(),
                };
                let json_set_app_port = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_PORT),
                    commandcontents: ap_bind_port.to_string(),
                };
                let json_start_command = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_START_COMMAND),
                    commandcontents: "".to_string(),
                };
                let serializedjson_addr =
                    serde_json::to_string(&json_set_app_addr).expect("problem serialising data");
                let serializedjson_port =
                    serde_json::to_string(&json_set_app_port).expect("problem serialising data");
                let serializedjson_start =
                    serde_json::to_string(&json_start_command).expect("problem serialising data");
                println!("About to send address, port and start command to keep-loader");
                let mut stream = UnixStream::connect(bind_socket).expect("failed to connect");
                stream
                    .write_all(&serializedjson_addr.as_bytes())
                    .expect("failed to write");
                stream
                    .write_all(&serializedjson_port.as_bytes())
                    .expect("failed to write");
                stream
                    .write_all(&serializedjson_start.as_bytes())
                    .expect("failed to write");
                //update the information about this keep-loader
                //first find the correct entry in the list
                for k in 0..kll.len() {
                    let keeploader = &kll[k];
                    //for mut keeploader in kll {
                    if keeploader.kuuid == kuuid {
                        println!("About to update state for keep-loader with kuuid {}, address {}, port {}", kuuid, &ap_bind_addr, ap_bind_port);
                        kll.remove(k);
                        let new_keeploader = KeepLoader {
                            state: KEEP_LOADER_STATE_STARTED,
                            kuuid,
                            app_loader_bind_port: ap_bind_port,
                            bindaddress: ap_bind_addr.to_string(),
                        };
                        kll.push(new_keeploader);
                        break;
                    }
                }
            }*/
            &_ => {}
        }
        println!(
            "Received a {:?} command",
            command_group.get(KEEP_COMMAND).unwrap()
        );
        Ok(json_reply)
    }
}
