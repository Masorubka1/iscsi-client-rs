// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    fmt::Debug,
    fs,
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use chrono::Utc;
use fastrace::collector::{Config, ConsoleReporter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{self, fs::File, io::AsyncWriteExt};
use tracing::{Event, Subscriber, span};
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{
    EnvFilter, Registry,
    fmt::{
        self, FmtContext, FormatEvent, FormatFields,
        format::{JsonFields, Writer},
        writer::BoxMakeWriter,
    },
    layer::{Layer, SubscriberExt},
    registry::LookupSpan,
};

#[derive(Debug, Deserialize, Clone)]
struct LoggerConfig {
    logger: LogConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
enum Output {
    Stdout,
    Stderr,
    File,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
enum RotationFreq {
    Minutely,
    Hourly,
    Daily,
    Never,
}

#[derive(Debug, Deserialize, Clone)]
struct LogFileConfig {
    path: String,
    #[serde(default)]
    rotation_frequency: Option<RotationFreq>,
}

#[derive(Debug, Deserialize, Clone)]
struct LogConfig {
    level: String,
    output: Output,
    is_show_line: bool,
    is_show_module_path: bool,
    is_show_target: bool,
    file: Option<LogFileConfig>,
}

#[derive(Default, Debug)]
struct SpanFields(pub serde_json::Map<String, serde_json::Value>);

struct CaptureSpanFieldsLayer;

impl<S> Layer<S> for CaptureSpanFieldsLayer
where S: Subscriber + for<'a> LookupSpan<'a>
{
    fn on_new_span(
        &self,
        attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut map = serde_json::Map::with_capacity(8);
            struct V<'a>(&'a mut serde_json::Map<String, serde_json::Value>);
            impl<'a> tracing::field::Visit for V<'a> {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn Debug) {
                    self.0
                        .insert(f.name().to_string(), json!(format!("{:?}", v)));
                }

                fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
                    self.0.insert(f.name().to_string(), json!(v));
                }

                fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
                    self.0.insert(f.name().to_string(), json!(v));
                }

                fn record_bool(&mut self, f: &tracing::field::Field, v: bool) {
                    self.0.insert(f.name().to_string(), json!(v));
                }

                fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                    self.0.insert(f.name().to_string(), json!(v));
                }
            }
            let mut vis = V(&mut map);
            attrs.record(&mut vis);
            span.extensions_mut().insert(SpanFields(map));
        }
    }

    fn on_record(
        &self,
        id: &span::Id,
        values: &span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<SpanFields>()
        {
            struct V<'a>(&'a mut serde_json::Map<String, serde_json::Value>);
            impl<'a> tracing::field::Visit for V<'a> {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn Debug) {
                    self.0
                        .insert(f.name().to_string(), json!(format!("{:?}", v)));
                }

                fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
                    self.0.insert(f.name().to_string(), json!(v));
                }

                fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
                    self.0.insert(f.name().to_string(), json!(v));
                }

                fn record_bool(&mut self, f: &tracing::field::Field, v: bool) {
                    self.0.insert(f.name().to_string(), json!(v));
                }

                fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                    self.0.insert(f.name().to_string(), json!(v));
                }
            }
            let mut vis = V(&mut fields.0);
            values.record(&mut vis);
        }
    }
}

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

/// Example usage:
/// let span = tracing::info_span!("my_span_after");
/// {
///     let _g = span.enter();
///     tracing::info!("info in span");
///     tracing::debug!("debug in span");
/// }
impl<S, N> FormatEvent<S, N> for JsonFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
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

        let mut fields = visitor.fields;

        if let Some(scope) = ctx.event_scope() {
            let mut span_names = Vec::with_capacity(8);
            for span in scope.from_root() {
                span_names.push(span.name().to_string());
                if let Some(ext) = span.extensions().get::<SpanFields>() {
                    for (k, v) in &ext.0 {
                        fields.entry(k.clone()).or_insert(v.clone());
                    }
                }
            }
            fields.insert("span_names".to_string(), json!(span_names));
        }

        let log_entry = LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: event.metadata().level().to_string(),
            target: if self.config.is_show_target {
                Some(event.metadata().target().to_string())
            } else {
                None
            },
            module_path: if self.config.is_show_module_path {
                Some(event.metadata().module_path().unwrap_or("").to_string())
            } else {
                None
            },
            line: if self.config.is_show_line {
                event.metadata().line()
            } else {
                None
            },
            fields,
        };

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
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn Debug) {
        self.fields
            .insert(field.name().to_string(), json!(format!("{:?}", value)));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
}

pub fn init_logger(config_path: &str) -> anyhow::Result<WorkerGuard> {
    let config_content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {config_path}"))?;
    let config: LoggerConfig = serde_yaml::from_str(&config_content)
        .with_context(|| format!("Failed to parse config file: {config_path}"))?;

    let (writer, guard) = make_writer(&config.logger)?;

    fastrace::set_reporter(ConsoleReporter, Config::default());
    let compat_layer = fastrace_tracing::FastraceCompatLayer::new();

    let env_filter = EnvFilter::try_new(&config.logger.level)
        .or_else(|_| EnvFilter::try_from_default_env())
        .context("Failed to parse log level from config or env")?;

    let json_layer = fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .json()
        .event_format(JsonFormatter::new(Arc::new(config.logger)))
        .fmt_fields(JsonFields::default());

    let subscriber = Registry::default()
        .with(env_filter)
        .with(compat_layer)
        .with(CaptureSpanFieldsLayer)
        .with(json_layer);

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set global default subscriber")?;

    Ok(guard)
}

fn make_writer(cfg: &LogConfig) -> anyhow::Result<(BoxMakeWriter, WorkerGuard)> {
    Ok(match cfg.output {
        Output::Stdout => {
            let (w, g) = tracing_appender::non_blocking(std::io::stdout());
            (BoxMakeWriter::new(w), g)
        },
        Output::Stderr => {
            let (w, g) = tracing_appender::non_blocking(std::io::stderr());
            (BoxMakeWriter::new(w), g)
        },
        Output::File => {
            let fcfg = cfg
                .file
                .clone()
                .context("log.file is required for output=file")?;
            let path = PathBuf::from(&fcfg.path);
            let dir = path.parent().unwrap_or_else(|| Path::new(""));

            let rotation = match fcfg.rotation_frequency.unwrap_or(RotationFreq::Never) {
                RotationFreq::Minutely => Rotation::MINUTELY,
                RotationFreq::Hourly => Rotation::HOURLY,
                RotationFreq::Daily => Rotation::DAILY,
                RotationFreq::Never => Rotation::NEVER,
            };

            let file_appender = RollingFileAppender::new(
                rotation,
                dir,
                path.file_name().unwrap_or_default(),
            );
            let (w, g) = tracing_appender::non_blocking(file_appender);
            (BoxMakeWriter::new(w), g)
        },
    })
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

pub async fn perform_save_to_file<P: AsRef<Path>, C: AsRef<[u8]>>(
    file_name: P,
    content: C,
) -> Result<()> {
    if let Some(parent_dir) = file_name.as_ref().parent() {
        tokio::fs::create_dir_all(parent_dir)
            .await
            .context("Failed to create directory for the file")?;
    }

    let mut file = File::create(&file_name)
        .await
        .context("Failed to create file")?;
    file.write_all(content.as_ref())
        .await
        .context("Failed to write content to file")?;

    Ok(())
}
