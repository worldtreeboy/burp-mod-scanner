package com.omnistrike.model;

public enum ModuleCategory {
    RECON("Recon"),
    INJECTION("Injection");

    private final String displayName;

    ModuleCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
