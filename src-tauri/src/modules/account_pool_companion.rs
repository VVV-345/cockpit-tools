//! 处理号池网页发起的一次性桌面操作，并在执行前要求本机用户确认。

use futures_util::StreamExt;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::AppHandle;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use url::Url;
use uuid::Uuid;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DesktopApplication {
    Codex,
    Cursor,
}

impl DesktopApplication {
    fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DesktopAction {
    Status,
    StartInstance {
        application: DesktopApplication,
        instance_id: String,
    },
    StopInstance {
        application: DesktopApplication,
        instance_id: String,
    },
    ApplyCodexCompact {
        instance_id: String,
        enabled: bool,
        model_context_window: Option<i64>,
        auto_compact_token_limit: Option<i64>,
        experimental_context_management: bool,
    },
    ConfigureCodexWsl {
        enabled: bool,
        config_dir: String,
    },
}

impl DesktopAction {
    fn summary(&self) -> String {
        match self {
            Self::Status => "读取本机 Codex 与 Cursor 实例状态".to_string(),
            Self::StartInstance {
                application,
                instance_id,
            } => format!("启动 {} 实例 {}", application.label(), instance_id),
            Self::StopInstance {
                application,
                instance_id,
            } => format!("停止 {} 实例 {}", application.label(), instance_id),
            Self::ApplyCodexCompact {
                instance_id,
                enabled,
                model_context_window,
                auto_compact_token_limit,
                experimental_context_management,
            } => format!(
                "修改 Codex 实例 {} 的本机 Compact 配置：enabled={}, context={:?}, compact={:?}, experimental_context_management={}",
                instance_id,
                enabled,
                model_context_window,
                auto_compact_token_limit,
                experimental_context_management
            ),
            Self::ConfigureCodexWsl {
                enabled,
                config_dir,
            } => format!(
                "修改 Codex WSL 同步配置：enabled={}, directory={}",
                enabled, config_dir
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct CompanionRequest {
    server_origin: String,
    ticket_id: Uuid,
    secret: String,
}

#[derive(Debug, Deserialize)]
struct TicketClaim {
    action: DesktopAction,
}

#[derive(Debug, Serialize)]
struct TicketSecret<'a> {
    secret: &'a str,
}

#[derive(Debug, Serialize)]
struct TicketCompletion<'a> {
    secret: &'a str,
    status: &'a str,
    result: Option<Value>,
    error: Option<String>,
}

pub fn handle_deep_links(app: &AppHandle, args: &[String]) -> bool {
    let mut handled = false;
    for value in args {
        if !is_account_pool_url(value) {
            continue;
        }
        handled = true;
        match parse_companion_url(value) {
            Ok(request) => {
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(error) = process_request(app_handle, request).await {
                        crate::modules::logger::log_warn(&format!(
                            "[AccountPool Companion] 操作未完成: {}",
                            error
                        ));
                    }
                });
            }
            Err(error) => crate::modules::logger::log_warn(&format!(
                "[AccountPool Companion] 深链接无效: {}",
                error
            )),
        }
    }
    handled
}

pub fn summarize_deep_link(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    (normalized.starts_with("cockpit-tools://account-pool")
        || normalized.starts_with("cockpittools://account-pool"))
    .then(|| "cockpit-tools://account-pool/<redacted>".to_string())
}

fn is_account_pool_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "cockpit-tools" | "cockpittools")
            && url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case("account-pool"))
    })
}

fn parse_companion_url(value: &str) -> Result<CompanionRequest, String> {
    let url = Url::parse(value).map_err(|_| "无法解析 URL".to_string())?;
    if !matches!(url.scheme(), "cockpit-tools" | "cockpittools")
        || !url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("account-pool"))
        || url.path() != "/execute"
    {
        return Err("不是受支持的号池桌面操作".to_string());
    }
    let server = url
        .query_pairs()
        .find_map(|(key, value)| (key == "server").then(|| value.into_owned()))
        .ok_or_else(|| "缺少 server".to_string())?;
    let ticket_id = url
        .query_pairs()
        .find_map(|(key, value)| (key == "ticket_id").then(|| value.into_owned()))
        .ok_or_else(|| "缺少 ticket_id".to_string())?
        .parse::<Uuid>()
        .map_err(|_| "ticket_id 无效".to_string())?;
    let secret = url.fragment().unwrap_or_default().to_string();
    if !(40..=128).contains(&secret.len())
        || !secret
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'_' || value == b'-')
    {
        return Err("票据密钥无效".to_string());
    }
    Ok(CompanionRequest {
        server_origin: validate_server_origin(&server)?,
        ticket_id,
        secret,
    })
}

fn validate_server_origin(value: &str) -> Result<String, String> {
    let url = Url::parse(value).map_err(|_| "服务器地址无效".to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "服务器地址缺少主机名".to_string())?;
    let local_http = url.scheme() == "http"
        && (host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback()));
    if url.scheme() != "https" && !local_http {
        return Err("服务器必须使用 HTTPS，本机回环地址可使用 HTTP".to_string());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("服务器地址必须是不含凭据、路径和参数的 origin".to_string());
    }
    Ok(url.origin().ascii_serialization())
}

async fn process_request(app: AppHandle, request: CompanionRequest) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| format!("创建 HTTPS 客户端失败: {}", error))?;
    let claim = claim_ticket(&client, &request).await?;
    let summary = claim.action.summary();
    let origin = request.server_origin.clone();
    let dialog_app = app.clone();
    let approved = tauri::async_runtime::spawn_blocking(move || {
        dialog_app
            .dialog()
            .message(format!(
                "站点 {} 请求执行以下本机操作：\n\n{}\n\n只在你刚刚从该站点发起操作时允许。",
                origin, summary
            ))
            .title("确认号池桌面操作")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "允许".to_string(),
                "拒绝".to_string(),
            ))
            .blocking_show()
    })
    .await
    .map_err(|error| format!("等待确认失败: {}", error))?;
    if !approved {
        report_completion(&client, &request, "cancelled", None, None).await?;
        return Ok(());
    }
    match execute_action(app.clone(), claim.action).await {
        Ok(result) => report_completion(&client, &request, "succeeded", Some(result), None).await,
        Err(error) => {
            let report_error = error.clone();
            report_completion(&client, &request, "failed", None, Some(report_error)).await?;
            Err(error)
        }
    }
}

async fn claim_ticket(
    client: &reqwest::Client,
    request: &CompanionRequest,
) -> Result<TicketClaim, String> {
    let response = client
        .post(format!(
            "{}/account_pool/desktop/tickets/{}/claim",
            request.server_origin, request.ticket_id
        ))
        .json(&TicketSecret {
            secret: &request.secret,
        })
        .send()
        .await
        .map_err(|error| format!("领取桌面操作失败: {}", error))?;
    if !response.status().is_success() {
        return Err(format!("领取桌面操作失败: HTTP {}", response.status()));
    }
    limited_json(response).await
}

async fn report_completion(
    client: &reqwest::Client,
    request: &CompanionRequest,
    status: &str,
    result: Option<Value>,
    error: Option<String>,
) -> Result<(), String> {
    let response = client
        .post(format!(
            "{}/account_pool/desktop/tickets/{}/complete",
            request.server_origin, request.ticket_id
        ))
        .json(&TicketCompletion {
            secret: &request.secret,
            status,
            result,
            error,
        })
        .send()
        .await
        .map_err(|request_error| format!("回传桌面操作结果失败: {}", request_error))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("回传桌面操作结果失败: HTTP {}", response.status()))
    }
}

async fn limited_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err("服务器响应超过 1 MiB".to_string());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("读取服务器响应失败: {}", error))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err("服务器响应超过 1 MiB".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("服务器响应格式无效: {}", error))
}

async fn execute_action(app: AppHandle, action: DesktopAction) -> Result<Value, String> {
    match action {
        DesktopAction::Status => {
            let codex_instances = crate::commands::codex_instance::codex_list_instances().await?;
            let cursor_instances =
                crate::commands::cursor_instance::cursor_list_instances().await?;
            let config = crate::modules::config::get_user_config();
            Ok(json!({
                "codex_instances": codex_instances,
                "cursor_instances": cursor_instances,
                "codex_wsl": {
                    "enabled": config.codex_sync_wsl,
                    "config_dir": config.codex_wsl_config_dir,
                }
            }))
        }
        DesktopAction::StartInstance {
            application,
            instance_id,
        } => match application {
            DesktopApplication::Codex => serde_json::to_value(
                crate::commands::codex_instance::codex_start_instance(app, instance_id, None, None)
                    .await?,
            )
            .map_err(|error| format!("序列化 Codex 实例状态失败: {}", error)),
            DesktopApplication::Cursor => serde_json::to_value(
                crate::commands::cursor_instance::cursor_start_instance(instance_id).await?,
            )
            .map_err(|error| format!("序列化 Cursor 实例状态失败: {}", error)),
        },
        DesktopAction::StopInstance {
            application,
            instance_id,
        } => match application {
            DesktopApplication::Codex => serde_json::to_value(
                crate::commands::codex_instance::codex_stop_instance(instance_id).await?,
            )
            .map_err(|error| format!("序列化 Codex 实例状态失败: {}", error)),
            DesktopApplication::Cursor => serde_json::to_value(
                crate::commands::cursor_instance::cursor_stop_instance(instance_id).await?,
            )
            .map_err(|error| format!("序列化 Cursor 实例状态失败: {}", error)),
        },
        DesktopAction::ApplyCodexCompact {
            instance_id,
            enabled,
            model_context_window,
            auto_compact_token_limit,
            experimental_context_management,
        } => {
            let previous = crate::commands::codex_instance::codex_get_instance_quick_config(
                instance_id.clone(),
            )
            .await?;
            let context_window = enabled.then_some(model_context_window.unwrap_or(1_000_000));
            let compact_limit = enabled.then_some(auto_compact_token_limit.unwrap_or(900_000));
            if compact_limit
                .zip(context_window)
                .is_some_and(|(limit, context)| limit >= context)
            {
                return Err("自动压缩阈值必须小于上下文窗口".to_string());
            }
            crate::commands::codex_instance::codex_save_instance_quick_config(
                instance_id.clone(),
                context_window,
                compact_limit,
                None,
                None,
                None,
            )
            .await?;
            match crate::commands::codex_instance::codex_save_instance_context_management(
                instance_id.clone(),
                experimental_context_management,
            )
            .await
            {
                Ok(saved) => serde_json::to_value(saved)
                    .map_err(|error| format!("序列化 Codex Compact 配置失败: {}", error)),
                Err(error) => {
                    let quick_rollback =
                        crate::commands::codex_instance::codex_save_instance_quick_config(
                            instance_id.clone(),
                            previous.detected_model_context_window,
                            previous.detected_auto_compact_token_limit,
                            None,
                            None,
                            None,
                        )
                        .await;
                    let context_rollback =
                        crate::commands::codex_instance::codex_save_instance_context_management(
                            instance_id,
                            previous.context_management_experimental_mode,
                        )
                        .await;
                    Err(format!(
                        "保存上下文管理设置失败: {}; 回滚结果: quick={:?}, context={:?}",
                        error,
                        quick_rollback.err(),
                        context_rollback.err()
                    ))
                }
            }
        }
        DesktopAction::ConfigureCodexWsl {
            enabled,
            config_dir,
        } => configure_codex_wsl(enabled, config_dir),
    }
}

fn configure_codex_wsl(enabled: bool, config_dir: String) -> Result<Value, String> {
    #[cfg(not(target_os = "windows"))]
    if enabled {
        return Err("WSL 同步仅支持 Windows".to_string());
    }

    let normalized = if enabled {
        validate_wsl_config_dir(&config_dir)?
    } else {
        String::new()
    };
    let previous = crate::modules::config::get_user_config();
    let saved = crate::modules::config::patch_user_config(|config| {
        config.codex_sync_wsl = enabled;
        config.codex_wsl_config_dir = normalized.clone();
        Ok(())
    })?;
    let synced_current_account = if enabled {
        match crate::modules::codex_account::sync_current_account_to_configured_wsl() {
            Ok(synced) => synced,
            Err(error) => {
                let rollback = crate::modules::config::patch_user_config(|config| {
                    config.codex_sync_wsl = previous.codex_sync_wsl;
                    config.codex_wsl_config_dir = previous.codex_wsl_config_dir.clone();
                    Ok(())
                });
                return Err(format!(
                    "同步当前 Codex 账号到 WSL 失败: {}; 配置回滚结果: {:?}",
                    error,
                    rollback.err()
                ));
            }
        }
    } else {
        false
    };
    Ok(json!({
        "enabled": saved.codex_sync_wsl,
        "config_dir": saved.codex_wsl_config_dir,
        "synced_current_account": synced_current_account,
    }))
}

fn validate_wsl_config_dir(value: &str) -> Result<String, String> {
    let normalized = value.trim().replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    if !(lower.starts_with("\\\\wsl$\\") || lower.starts_with("\\\\wsl.localhost\\"))
        || !lower.ends_with("\\.codex")
        || normalized
            .split('\\')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(
            "WSL 配置目录必须是以 .codex 结尾的 \\\\wsl$ 或 \\\\wsl.localhost UNC 路径".to_string(),
        );
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secure_companion_link_without_putting_secret_in_the_query() {
        let ticket_id = Uuid::new_v4();
        let link = format!(
            "cockpit-tools://account-pool/execute?server=https%3A%2F%2Fredstars.ai&ticket_id={}#{}",
            ticket_id,
            "s".repeat(43)
        );
        let parsed = parse_companion_url(&link).expect("valid companion link");

        assert_eq!(parsed.server_origin, "https://redstars.ai");
        assert_eq!(parsed.ticket_id, ticket_id);
        assert_eq!(parsed.secret, "s".repeat(43));
        assert_eq!(
            summarize_deep_link(&link).as_deref(),
            Some("cockpit-tools://account-pool/<redacted>")
        );
    }

    #[test]
    fn redacts_malformed_account_pool_links_before_logging() {
        assert_eq!(
            summarize_deep_link("cockpit-tools://account-pool/not-supported#secret").as_deref(),
            Some("cockpit-tools://account-pool/<redacted>")
        );
    }

    #[test]
    fn rejects_remote_plain_http_and_urls_with_paths() {
        assert!(validate_server_origin("http://example.com").is_err());
        assert!(validate_server_origin("https://example.com/path").is_err());
        assert_eq!(
            validate_server_origin("http://127.0.0.1:4000").expect("loopback HTTP is allowed"),
            "http://127.0.0.1:4000"
        );
    }

    #[test]
    fn accepts_only_a_codex_directory_inside_a_wsl_unc_share() {
        assert_eq!(
            validate_wsl_config_dir(r"\\wsl.localhost\Ubuntu\home\user\.codex")
                .expect("valid WSL directory"),
            r"\\wsl.localhost\Ubuntu\home\user\.codex"
        );
        assert!(validate_wsl_config_dir(r"C:\Users\user\.codex").is_err());
        assert!(validate_wsl_config_dir(r"\\server\share\.codex").is_err());
        assert!(validate_wsl_config_dir(r"\\wsl$\Ubuntu\home\user\..\.codex").is_err());
    }
}
