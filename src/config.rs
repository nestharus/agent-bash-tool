//! Static machine configuration for the installed agent-bash binary.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const AGENT_BASH_CONFIG_FILE_NAME: &str = "agent-bash.toml";
const AGENT_RUNNER_CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryConfig {
    pub(crate) state_root: PathBuf,
    pub(crate) agent_runner_bin: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentRunnerRuntimeConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) config_home: PathBuf,
}

pub(crate) fn load() -> Result<Option<BinaryConfig>, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not resolve the current executable: {error}"))?;
    load_for_executable(&executable)
}

fn load_for_executable(executable: &Path) -> Result<Option<BinaryConfig>, String> {
    let executable = std::fs::canonicalize(executable).map_err(|error| {
        format!(
            "could not canonicalize executable {}: {error}",
            executable.display()
        )
    })?;
    let directory = executable.parent().ok_or_else(|| {
        format!(
            "could not resolve the directory containing executable {}",
            executable.display()
        )
    })?;
    let path = directory.join(AGENT_BASH_CONFIG_FILE_NAME);
    match path.try_exists() {
        Ok(false) => Ok(None),
        Ok(true) => read_config(&path).map(Some),
        Err(error) => Err(format!(
            "could not inspect agent-bash config {}: {error}",
            path.display()
        )),
    }
}

fn read_config(path: &Path) -> Result<BinaryConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read agent-bash config {}: {error}",
            path.display()
        )
    })?;
    let config: BinaryConfig = toml::from_str(&text).map_err(|error| {
        format!(
            "could not parse agent-bash config {}: {error}",
            path.display()
        )
    })?;
    require_absolute(path, "state_root", &config.state_root)?;
    require_absolute(path, "agent_runner_bin", &config.agent_runner_bin)?;
    Ok(config)
}

pub(crate) fn load_agent_runner_runtime_config(
    agent_runner_bin: &Path,
) -> Result<Option<AgentRunnerRuntimeConfig>, String> {
    let directory = agent_runner_bin.parent().ok_or_else(|| {
        format!(
            "could not resolve the directory containing configured agent runner {}",
            agent_runner_bin.display()
        )
    })?;
    let path = directory.join(AGENT_RUNNER_CONFIG_FILE_NAME);
    match path.try_exists() {
        Ok(false) => Ok(None),
        Ok(true) => read_agent_runner_runtime_config(&path).map(Some),
        Err(error) => Err(format!(
            "could not inspect agent runner config {}: {error}",
            path.display()
        )),
    }
}

fn read_agent_runner_runtime_config(path: &Path) -> Result<AgentRunnerRuntimeConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read agent runner config {}: {error}",
            path.display()
        )
    })?;
    let config: AgentRunnerRuntimeConfig = toml::from_str(&text).map_err(|error| {
        format!(
            "could not parse agent runner config {}: {error}",
            path.display()
        )
    })?;
    require_absolute(path, "data_dir", &config.data_dir)?;
    require_absolute(path, "config_home", &config.config_home)?;
    Ok(config)
}

fn require_absolute(source: &Path, field: &str, value: &Path) -> Result<(), String> {
    if value.is_absolute() {
        return Ok(());
    }
    Err(format!(
        "configuration {} field {field} must be an absolute path",
        source.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_config_is_loaded_and_validated() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("agent-bash");
        std::fs::write(&executable, "fixture").unwrap();
        let state_root = directory.path().join("state");
        let agent_runner_bin = directory.path().join("runner");
        std::fs::write(
            directory.path().join(AGENT_BASH_CONFIG_FILE_NAME),
            format!(
                "state_root = {:?}\nagent_runner_bin = {:?}\n",
                state_root.display().to_string(),
                agent_runner_bin.display().to_string()
            ),
        )
        .unwrap();

        assert_eq!(
            load_for_executable(&executable).unwrap(),
            Some(BinaryConfig {
                state_root,
                agent_runner_bin,
            })
        );
    }

    #[test]
    fn absent_adjacent_config_selects_environment_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("agent-bash");
        std::fs::write(&executable, "fixture").unwrap();

        assert_eq!(load_for_executable(&executable).unwrap(), None);
    }

    #[test]
    fn invalid_adjacent_config_does_not_fall_back() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("agent-bash");
        std::fs::write(&executable, "fixture").unwrap();
        std::fs::write(
            directory.path().join(AGENT_BASH_CONFIG_FILE_NAME),
            "state_root = [",
        )
        .unwrap();

        assert!(load_for_executable(&executable).is_err());
    }

    #[test]
    fn configured_agent_runner_roots_are_loaded_from_its_adjacent_file() {
        let directory = tempfile::tempdir().unwrap();
        let runner_dir = directory.path().join("runner");
        std::fs::create_dir_all(&runner_dir).unwrap();
        let executable = runner_dir.join("agents");
        std::fs::write(&executable, "fixture").unwrap();
        let data_dir = directory.path().join("data");
        let config_home = directory.path().join("config");
        std::fs::write(
            runner_dir.join(AGENT_RUNNER_CONFIG_FILE_NAME),
            format!(
                "data_dir = {:?}\nconfig_home = {:?}\n",
                data_dir.display().to_string(),
                config_home.display().to_string()
            ),
        )
        .unwrap();

        assert_eq!(
            load_agent_runner_runtime_config(&executable).unwrap(),
            Some(AgentRunnerRuntimeConfig {
                data_dir,
                config_home,
            })
        );
    }

    #[test]
    fn colocated_agent_bash_and_runner_configs_remain_distinct() {
        let directory = tempfile::tempdir().unwrap();
        let agent_bash = directory.path().join("agent-bash");
        let agent_runner = directory.path().join("agents");
        std::fs::write(&agent_bash, "fixture").unwrap();
        std::fs::write(&agent_runner, "fixture").unwrap();
        let state_root = directory.path().join("state");
        let data_dir = directory.path().join("data");
        let config_home = directory.path().join("config");
        std::fs::write(
            directory.path().join(AGENT_BASH_CONFIG_FILE_NAME),
            format!(
                "state_root = {:?}\nagent_runner_bin = {:?}\n",
                state_root.display().to_string(),
                agent_runner.display().to_string()
            ),
        )
        .unwrap();
        std::fs::write(
            directory.path().join(AGENT_RUNNER_CONFIG_FILE_NAME),
            format!(
                "data_dir = {:?}\nconfig_home = {:?}\n",
                data_dir.display().to_string(),
                config_home.display().to_string()
            ),
        )
        .unwrap();

        assert_eq!(
            load_for_executable(&agent_bash).unwrap(),
            Some(BinaryConfig {
                state_root,
                agent_runner_bin: agent_runner.clone(),
            })
        );
        assert_eq!(
            load_agent_runner_runtime_config(&agent_runner).unwrap(),
            Some(AgentRunnerRuntimeConfig {
                data_dir,
                config_home,
            })
        );
    }
}
