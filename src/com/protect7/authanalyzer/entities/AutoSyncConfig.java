package com.protect7.authanalyzer.entities;

public class AutoSyncConfig {

	private String triggerHeaderName;
	private String triggerHeaderValue;
	private String sourceHeaderName;
	private String extractionRegex;
	private String targetTokenName;
	private String targetHost = "";
	private String currentValue = "";
	
	public AutoSyncConfig(String triggerHeaderName, String triggerHeaderValue, String sourceHeaderName,
			String extractionRegex, String targetTokenName) {
		this(triggerHeaderName, triggerHeaderValue, sourceHeaderName, extractionRegex, targetTokenName, "");
	}

	public AutoSyncConfig(String triggerHeaderName, String triggerHeaderValue, String sourceHeaderName,
			String extractionRegex, String targetTokenName, String targetHost) {
		this.triggerHeaderName = triggerHeaderName;
		this.triggerHeaderValue = triggerHeaderValue;
		this.sourceHeaderName = sourceHeaderName;
		this.extractionRegex = extractionRegex;
		this.targetTokenName = targetTokenName;
		this.targetHost = targetHost != null ? targetHost : "";
	}

	public String getTriggerHeaderName() {
		return triggerHeaderName;
	}

	public void setTriggerHeaderName(String triggerHeaderName) {
		this.triggerHeaderName = triggerHeaderName;
	}

	public String getTriggerHeaderValue() {
		return triggerHeaderValue;
	}

	public void setTriggerHeaderValue(String triggerHeaderValue) {
		this.triggerHeaderValue = triggerHeaderValue;
	}

	public String getSourceHeaderName() {
		return sourceHeaderName;
	}

	public void setSourceHeaderName(String sourceHeaderName) {
		this.sourceHeaderName = sourceHeaderName;
	}

	public String getExtractionRegex() {
		return extractionRegex;
	}

	public void setExtractionRegex(String extractionRegex) {
		this.extractionRegex = extractionRegex;
	}

	public String getTargetTokenName() {
		return targetTokenName;
	}

	public void setTargetTokenName(String targetTokenName) {
		this.targetTokenName = targetTokenName;
	}

	public String getTargetHost() {
		return targetHost;
	}

	public void setTargetHost(String targetHost) {
		this.targetHost = targetHost != null ? targetHost : "";
	}

	public String getCurrentValue() {
		return currentValue;
	}

	public void setCurrentValue(String currentValue) {
		this.currentValue = currentValue;
	}
}