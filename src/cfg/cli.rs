// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn resolve_config_path(rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel);

    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .context("cannot get current working dir")?
            .join(p)
    };

    let canon = abs
        .canonicalize()
        .with_context(|| format!("failed to canonicalize path {abs:?}"))?;

    Ok(canon)
}
