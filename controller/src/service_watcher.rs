use chrono::Utc;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{
    runtime::{ watcher, WatchStreamExt},
    Api, Client, ResourceExt,
};
use serde_json::json;
use tracing::{warn,error};
use tracing::info;
use crate::{api_post_call, Error,  SvcDetail};


pub async fn watch_service() -> Result<(), Error> {
    let c = Client::try_default().await?;
    let svc: Api<Service> = Api::all(c.clone());
    let wc = watcher::Config::default();
    watcher(svc, wc)
        .applied_objects()
        .default_backoff()
        .try_for_each(|p| {
            async move {
                if let Some(unready_reason) = svc_unready(&p) {
                    warn!("{}", unready_reason);
                } else {
                    info!("SVC  {} Ready", p.name_any());

                    let ep = update_serviceinfo(p).await;
                    // log the error and proceed
                    if let Err(e) = ep {
                        error!(
                            "Failed while updating the endpoint slice info {}",
                            e.to_string()
                        );
                    }
                }
                Ok(())
            }
        })
        .await?;

    Ok(())
}

async fn update_serviceinfo(svc: Service) -> Result<(), Error> {
    let svc_name = svc.name_any();
    let svc_namespace = svc.metadata.namespace.to_owned();
    let svc_spec = &svc.spec;
    let svc_ip = svc_spec.as_ref().unwrap().cluster_ip.as_ref().unwrap();

    let z = SvcDetail {
        svc_ip: svc_ip.to_owned(),
        svc_name: svc_name.to_owned(),
        svc_namespace: svc_namespace.to_owned(),
        service_spec: Some(json!(svc)),
        time_stamp: Utc::now().naive_utc(),
    };
    api_post_call(json!(z), "netpol/svc").await?;
    Ok(())
}

fn svc_unready(p: &Service) -> Option<String> {
    let status = p.status.as_ref().unwrap();
    info!("Service Status {:?}", status);
    if let Some(conds) = &status.conditions {
        let failed = conds
            .iter()
            .filter(|c| c.type_ == "Ready" && c.status == "False")
            .map(|c| c.message.clone())
            .collect::<Vec<_>>()
            .join(",");
        if !failed.is_empty() {
            return Some(format!("Unready Service {}: {}", p.name_any(), failed));
        }
    }
    None
}