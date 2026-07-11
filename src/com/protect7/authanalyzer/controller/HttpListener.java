package com.protect7.authanalyzer.controller;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.Setting;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) {
			boolean syncFromAllTools = Setting.getValueAsBoolean(Setting.Item.LIVE_PROXY_SYNC_FROM_ALL_TOOLS);
			if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || syncFromAllTools) {
				performLiveProxySync(messageInfo);
			}
		}

		if(config.isRunning() && (!messageIsRequest || (messageIsRequest && config.isDropOriginal() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))) {
			if(!isFiltered(toolFlag, messageInfo)) {
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}
	}

	public static void performLiveProxySync(IHttpRequestResponse messageInfo) {
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		List<String> headers = requestInfo.getHeaders();

		for(com.protect7.authanalyzer.entities.Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			if (session.getAutoSyncList() == null || session.getAutoSyncList().isEmpty()) continue;

			for(com.protect7.authanalyzer.entities.AutoSyncConfig syncConfig : session.getAutoSyncList()) {
				// Check trigger
				boolean triggerMatched = false;
				for (String header : headers) {
					if (header.toLowerCase().startsWith(syncConfig.getTriggerHeaderName().toLowerCase() + ":")) {
						String value = header.substring(header.indexOf(":") + 1).trim();
						if (syncConfig.getTriggerHeaderValue().isEmpty() || value.equalsIgnoreCase(syncConfig.getTriggerHeaderValue())) {
							triggerMatched = true;
							break;
						}
					}
				}

				if (triggerMatched) {
					// Extract value from source header
					String extractedValue = null;
					for (String header : headers) {
						if (header.toLowerCase().startsWith(syncConfig.getSourceHeaderName().toLowerCase() + ":")) {
							String sourceValue = header.substring(header.indexOf(":") + 1).trim();

							if (syncConfig.getExtractionRegex() != null && !syncConfig.getExtractionRegex().isEmpty()) {
								try {
									Pattern pattern = Pattern.compile(syncConfig.getExtractionRegex());
									Matcher matcher = pattern.matcher(sourceValue);
									if (matcher.find()) {
										if (matcher.groupCount() >= 1) {
											extractedValue = matcher.group(1);
										} else {
											extractedValue = matcher.group(0);
										}
									}
								} catch (Exception e) {
									BurpExtender.callbacks.printError("Invalid regex in Live Proxy Sync: " + e.getMessage());
								}
							} else if (syncConfig.getSourceHeaderName().equalsIgnoreCase("Cookie")) {
								// Robust case-insensitive cookie parsing
								String[] cookies = sourceValue.split(";");
								for (String cookie : cookies) {
									cookie = cookie.trim();
									int eqIndex = cookie.indexOf("=");
									if (eqIndex != -1) {
										String name = cookie.substring(0, eqIndex).trim();
										String val = cookie.substring(eqIndex + 1).trim();
										if (name.equalsIgnoreCase(syncConfig.getTargetTokenName())) {
											extractedValue = val;
											break;
										}
									}
								}
								// Fallback if not found in split
								if (extractedValue == null) {
									extractedValue = sourceValue;
								}
							} else {
								extractedValue = sourceValue;
							}
							break;
						}
					}

					if (extractedValue != null) {
						// Store the extracted value privately inside AutoSyncConfig!
						if (syncConfig.getCurrentValue() == null || !syncConfig.getCurrentValue().equals(extractedValue)) {
							syncConfig.setCurrentValue(extractedValue);
							BurpExtender.callbacks.issueAlert("[Live Proxy Sync] Session '" + session.getName() + "' updated sync token '" + syncConfig.getTargetTokenName() + "' to '" + extractedValue + "'.");
						}
					}
				}
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}

	private boolean isFiltered(int toolFlag, IHttpRequestResponse messageInfo) {
		boolean isFiltered = false;
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		IResponseInfo responseInfo = null;
		if(messageInfo.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		}
		for(int i=0; i<config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if(filter.filterRequest(BurpExtender.callbacks, toolFlag, requestInfo, responseInfo)) {
				return true;
			}
		}
		return isFiltered;
	}
}