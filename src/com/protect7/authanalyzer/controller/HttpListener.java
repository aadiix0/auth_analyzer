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
import javax.swing.SwingUtilities;
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

		if(config.isRunning() && config.getAnalyzerState() == CurrentConfig.AnalyzerState.ALL_TRAFFIC && (!messageIsRequest || (messageIsRequest && config.isDropOriginal() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))) {
			if(!isFiltered(toolFlag, messageInfo)) {
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}
	}

	public static void performLiveProxySync(IHttpRequestResponse messageInfo) {
		try {
			if (BurpExtender.mainPanel == null || BurpExtender.mainPanel.getConfigurationPanel() == null) {
				return;
			}
			com.protect7.authanalyzer.gui.main.ConfigurationPanel configPanel = BurpExtender.mainPanel.getConfigurationPanel();
			IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
			List<String> headers = requestInfo.getHeaders();
			if (headers == null) return;

			String requestHost = null;
			if (messageInfo.getHttpService() != null) {
				requestHost = messageInfo.getHttpService().getHost();
			}
			if (requestHost == null || requestHost.isEmpty()) {
				if (requestInfo.getUrl() != null) {
					requestHost = requestInfo.getUrl().getHost();
				}
			}
			if (requestHost == null || requestHost.isEmpty()) {
				for (String header : headers) {
					if (header != null && header.toLowerCase().startsWith("host:")) {
						String val = header.substring(5).trim();
						int colonIndex = val.indexOf(":");
						if (colonIndex != -1) {
							requestHost = val.substring(0, colonIndex).trim();
						} else {
							requestHost = val;
						}
						break;
					}
				}
			}

			for (String sessionName : configPanel.getSessionNames()) {
				com.protect7.authanalyzer.gui.entity.SessionPanel sessionPanel = configPanel.getSessionPanelByName(sessionName);
				if (sessionPanel == null || sessionPanel.getAutoSyncList() == null || sessionPanel.getAutoSyncList().isEmpty()) continue;

				for(com.protect7.authanalyzer.entities.AutoSyncConfig syncConfig : sessionPanel.getAutoSyncList()) {
					if (syncConfig == null) continue;
					if (!isHostMatch(requestHost, syncConfig.getTargetHost())) {
						continue;
					}
					String triggerName = syncConfig.getTriggerHeaderName();
					String triggerVal = syncConfig.getTriggerHeaderValue();
					String sourceName = syncConfig.getSourceHeaderName();
					String targetName = syncConfig.getTargetTokenName();

					if (triggerName == null || triggerName.trim().isEmpty() ||
						sourceName == null || sourceName.trim().isEmpty() ||
						targetName == null || targetName.trim().isEmpty()) {
						continue;
					}

					// Check trigger
					boolean triggerMatched = false;
					for (String header : headers) {
						if (header != null && header.toLowerCase().startsWith(triggerName.toLowerCase() + ":")) {
							String value = header.substring(header.indexOf(":") + 1).trim();
							if (isTriggerValueMatch(value, triggerVal)) {
								triggerMatched = true;
								break;
							}
						}
					}

					if (triggerMatched) {
						// Extract value from source header
						String extractedValue = null;
						for (String header : headers) {
							if (header != null && header.toLowerCase().startsWith(sourceName.toLowerCase() + ":")) {
								String sourceValue = header.substring(header.indexOf(":") + 1).trim();

								if (!isValueFilterMatch(sourceValue, syncConfig.getValueFilter())) {
									break;
								}

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
								} else if (sourceName.equalsIgnoreCase("Cookie")) {
									// Robust case-insensitive cookie parsing
									String[] cookies = sourceValue.split(";");
									for (String cookie : cookies) {
										cookie = cookie.trim();
										int eqIndex = cookie.indexOf("=");
										if (eqIndex != -1) {
											String name = cookie.substring(0, eqIndex).trim();
											String val = cookie.substring(eqIndex + 1).trim();
											if (name.equalsIgnoreCase(targetName.trim())) {
												extractedValue = val;
												break;
											}
										}
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
								BurpExtender.callbacks.issueAlert("[Live Proxy Sync] Session '" + sessionName + "' updated sync token '" + targetName + "' to '" + extractedValue + "'.");
							}

							// Update the running Session object's currentValue if it is running
							com.protect7.authanalyzer.entities.Session runningSession = CurrentConfig.getCurrentConfig().getSessionByName(sessionName);
							if (runningSession != null && runningSession.getAutoSyncList() != null) {
								for (com.protect7.authanalyzer.entities.AutoSyncConfig runConfig : runningSession.getAutoSyncList()) {
									if (runConfig.getTargetTokenName().equalsIgnoreCase(targetName.trim())) {
										runConfig.setCurrentValue(extractedValue);
									}
								}
							}

							// Also update UI display in StatusPanel in real-time if visible!
							if (runningSession != null && runningSession.getStatusPanel() != null) {
								final com.protect7.authanalyzer.entities.AutoSyncConfig finalSyncConfig = syncConfig;
								SwingUtilities.invokeLater(() -> {
									try {
										runningSession.getStatusPanel().updateSyncConfigStatus(finalSyncConfig);
									} catch (Exception e) {
										// Safe catch
									}
								});
							}
						}
					}
				}
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printError("Error in Live Proxy Sync active listening: " + e.getMessage());
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		try {
			if (messageIsRequest && message != null && message.getMessageInfo() != null) {
				// Trigger Live Proxy Sync at the earliest proxy stage, before other extensions strip headers!
				performLiveProxySync(message.getMessageInfo());
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printError("Error triggering performLiveProxySync in processProxyMessage: " + e.getMessage());
		}

		if(config.isDropOriginal() && messageIsRequest && config.getAnalyzerState() == CurrentConfig.AnalyzerState.ALL_TRAFFIC) {
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}

	public static boolean isTriggerValueMatch(String headerValue, String triggerValConfig) {
		if (triggerValConfig == null || triggerValConfig.trim().isEmpty()) {
			return true;
		}
		if (headerValue == null) {
			return false;
		}
		return headerValue.trim().equalsIgnoreCase(triggerValConfig.trim());
	}

	public static boolean isValueFilterMatch(String sourceValue, String valueFilterConfig) {
		if (valueFilterConfig == null || valueFilterConfig.trim().isEmpty()) {
			return true;
		}
		if (sourceValue == null) {
			return false;
		}
		String val = sourceValue.trim();
		String filter = valueFilterConfig.trim();

		if (val.equalsIgnoreCase(filter)) {
			return true;
		}
		if (val.toLowerCase().startsWith(filter.toLowerCase())) {
			return true;
		}
		if (val.toLowerCase().contains(filter.toLowerCase())) {
			return true;
		}
		try {
			if (Pattern.compile(filter, Pattern.CASE_INSENSITIVE).matcher(val).find()) {
				return true;
			}
		} catch (Exception e) {
			// Ignore invalid regex
		}
		return false;
	}

	public static boolean isHostMatch(String requestHost, String targetHostConfig) {
		if (targetHostConfig == null || targetHostConfig.trim().isEmpty()) {
			return true;
		}
		if (requestHost == null || requestHost.trim().isEmpty()) {
			return false;
		}
		String host = requestHost.trim().toLowerCase();
		String[] targetPatterns = targetHostConfig.split(",");
		for (String rawPattern : targetPatterns) {
			String pattern = rawPattern.trim().toLowerCase();
			if (pattern.isEmpty()) continue;

			if (host.equals(pattern)) {
				return true;
			}
			if (host.contains(pattern)) {
				return true;
			}
			if (pattern.contains("*")) {
				String regex = "^" + Pattern.quote(pattern).replace("*", "\\E.*\\Q") + "$";
				try {
					if (Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(host).matches()) {
						return true;
					}
				} catch (Exception e) {
					// Ignore invalid regex
				}
			}
			try {
				if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(host).find()) {
					return true;
				}
			} catch (Exception e) {
				// Ignore invalid regex
			}
		}
		return false;
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