use crate::Config;

/// Severity of an assertion result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A single assertion finding.
#[derive(Debug)]
pub struct AssertionResult {
    pub check_name: String,
    pub severity: Severity,
    pub field: String,
    pub message: String,
}

impl AssertionResult {
    pub fn error(check: &str, field: &str, message: impl Into<String>) -> Self {
        Self {
            check_name: check.to_string(),
            severity: Severity::Error,
            field: field.to_string(),
            message: message.into(),
        }
    }

    pub fn warning(check: &str, field: &str, message: impl Into<String>) -> Self {
        Self {
            check_name: check.to_string(),
            severity: Severity::Warning,
            field: field.to_string(),
            message: message.into(),
        }
    }
}

/// Category for grouping checks in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Structural,
    KernelCmdline,
    Verity,
    BinaryRemoval,
    ModuleSecurity,
    Firewall,
    Network,
    ServiceHardening,
    MountSecurity,
    Logging,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Self::Structural => "Structural",
            Self::KernelCmdline => "Kernel Cmdline",
            Self::Verity => "Verity",
            Self::BinaryRemoval => "Binary Removal",
            Self::ModuleSecurity => "Module Security",
            Self::Firewall => "Firewall",
            Self::Network => "Network",
            Self::ServiceHardening => "Service Hardening",
            Self::MountSecurity => "Mount Security",
            Self::Logging => "Logging",
        }
    }
}

/// Metadata about a registered check.
pub struct CheckInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub check: fn(&Config) -> Vec<AssertionResult>,
}
