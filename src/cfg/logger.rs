use std::{collections::HashMap, fmt::Debug, fs, future::Future, path::Path, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{self, fs::File, io::AsyncWriteExt};
use tracing::{Event, Subscriber};
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        self, FmtContext, FormatEvent, FormatFields, FormattedFields,
        format::{FmtSpan, JsonFields, Writer},
    },
    layer::SubscriberExt,
};

// Config logger
#[derive(Debug, Deserialize, Clone)]
struct LoggerConfig {
    logger: LogConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct LogConfig {
    level: String,
    output: String,
    is_show_line: bool,
    is_show_module_path: bool,
    is_show_target: bool,
    file: Option<LogFileConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct LogFileConfig {
    path: String,
    rotation_frequency: Option<String>,
}

// Define custom layer for reading tracing events in json format
struct JsonFormatter {
    config: Arc<LogConfig>,
}

impl JsonFormatter {
    fn new(config: Arc<LogConfig>) -> Self {
        Self { config }
    }
}

#[derive(Serialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl LogEntry {
    fn new(
        config: &LogConfig,
        event: &Event,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: event.metadata().level().to_string(),
            target: if config.is_show_target {
                Some(event.metadata().target().to_string())
            } else {
                None
            },
            module_path: if config.is_show_module_path {
                Some(event.metadata().module_path().unwrap_or("").to_string())
            } else {
                None
            },
            line: if config.is_show_line {
                event.metadata().line()
            } else {
                None
            },
            fields,
        }
    }
}

/// Example of usage:
/// let span = tracing::span!(tracing::Level::INFO, "my_span_after");
/// {
///     tracing::info!("This is an info message within a span");
///     tracing::debug!("This is an debug message within a span");
///     tracing::trace!("This is an trace message within a span");
///     tracing::warn!("This is a warning message");
///     tracing::error!("This is an error message");
/// }.instrument(span);
impl<S, N> FormatEvent<S, N> for JsonFormatter
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);

        let mut fields = visitor.fields.clone();

        let parent_span = ctx.event_scope();
        if let Some(scope) = parent_span {
            let mut span_names = vec![];
            for span in scope.from_root() {
                span_names.push(span.name().to_string());
                if let Some(ext) = span.extensions().get::<FormattedFields<JsonFields>>()
                {
                    let v: HashMap<String, Value> =
                        serde_json::from_str(&ext.fields).unwrap_or_default();
                    for (key, value) in v {
                        fields.insert(key.clone(), value.clone());
                    }
                }
            }
            fields.insert("span_names".to_string(), json!(span_names));
        }

        let log_entry = LogEntry::new(&self.config, event, fields);
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&log_entry).map_err(|_| std::fmt::Error)?
        )
    }
}

#[derive(Default)]
struct JsonVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        self.fields
            .insert(field.name().to_string(), json!(format!("{:?}", value)));
    }
}

pub fn init_logger(config_path: &str) -> anyhow::Result<WorkerGuard> {
    let config_content = fs::read_to_string(config_path)
        .context(format!("Failed to read config file: {config_path}"))?;
    let config: LoggerConfig = serde_yaml::from_str(&config_content)
        .context(format!("Failed to parse config file: {config_path}"))?;

    let (file_writer, guard) = match config.logger.output.as_str() {
        "stdout" => {
            let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
            (non_blocking, guard)
        },
        "stderr" => {
            let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stderr());
            (non_blocking, guard)
        },
        "file" => {
            let cfg = &config
                .logger
                .file
                .clone()
                .context("Failed to find log config file")?;

            let split_path = |path: &str| -> (String, String) {
                let path = Path::new(path);
                let directory = path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .to_str()
                    .unwrap_or("")
                    .to_string();
                let file_name = path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new(""))
                    .to_str()
                    .unwrap_or("")
                    .to_string();
                (directory, file_name)
            };

            let rotation = match cfg.rotation_frequency.as_deref() {
                Some("minutely") => Rotation::MINUTELY,
                Some("hourly") => Rotation::HOURLY,
                Some("daily") => Rotation::DAILY,
                _ => Rotation::NEVER,
            };
            let file_appender = RollingFileAppender::new(
                rotation,
                split_path(&cfg.path).0,
                split_path(&cfg.path).1,
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            (non_blocking, guard)
        },
        _ => {
            return Err(anyhow::anyhow!("Invalid log output specified"));
        },
    };

    let subscriber_layer = fmt::layer()
        .with_writer(move || file_writer.clone())
        .with_ansi(true)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .json()
        .event_format(JsonFormatter::new(Arc::new(config.logger.clone())))
        .fmt_fields(JsonFields::default());

    let env_filter = EnvFilter::try_new(&config.logger.level)
        .context("Failed to parse log level from config")?;

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(subscriber_layer);

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set global default subscriber")?;

    Ok(guard)
}

pub trait LoggableToFile {
    fn get_name() -> &'static str {
        "unknown"
    }

    fn save_to_file(
        file_name: &str,
        content: &str,
    ) -> impl Future<Output = Result<()>> + Send {
        perform_save_to_file(file_name, content)
    }
}

pub async fn perform_save_to_file(file_name: &str, content: &str) -> Result<()> {
    if let Some(parent_dir) = Path::new(file_name).parent() {
        tokio::fs::create_dir_all(parent_dir)
            .await
            .context("Failed to create directory for the file")?;
    }

    let mut file = File::create(file_name)
        .await
        .context("Failed to create file")?;
    file.write_all(content.as_bytes())
        .await
        .context("Failed to write content to file")?;

    Ok(())
}
