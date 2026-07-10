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
						if (syncConfig.getTriggerHeaderValue().isEmpty() || value.equals(syncConfig.getTriggerHeaderValue())) {
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
						// Check if Target Token exists
						com.protect7.authanalyzer.entities.Token targetToken = null;
						for (com.protect7.authanalyzer.entities.Token token : session.getTokens()) {
							if (token.getName().equalsIgnoreCase(syncConfig.getTargetTokenName())) {
								targetToken = token;
								break;
							}
						}

						boolean isNewToken = false;
						if (targetToken == null) {
							isNewToken = true;
							// Token doesn't exist, let's create and add it on-the-fly!
							targetToken = new com.protect7.authanalyzer.entities.TokenBuilder()
									.setName(syncConfig.getTargetTokenName())
									.setIsAutoExtract(true)
									.setExtractName(syncConfig.getTargetTokenName())
									.setValue(extractedValue)
									.build();
							session.getTokens().add(targetToken);

							// Also update UI TokenPanel so it shows up in UI
							final String finalExtractedValue = extractedValue;
							SwingUtilities.invokeLater(() -> {
								try {
									com.protect7.authanalyzer.gui.entity.SessionPanel sessionPanel = BurpExtender.mainPanel.getConfigurationPanel().getSessionPanelByName(session.getName());
									if (sessionPanel != null) {
										boolean tokenPanelExists = false;
										for (com.protect7.authanalyzer.gui.entity.TokenPanel tokenPanel : sessionPanel.getTokenPanelList()) {
											if (tokenPanel.getTokenName().equalsIgnoreCase(syncConfig.getTargetTokenName())) {
												tokenPanelExists = true;
												break;
											}
										}
										if (!tokenPanelExists) {
											com.protect7.authanalyzer.gui.entity.TokenPanel newTokenPanel = sessionPanel.addToken(syncConfig.getTargetTokenName());
											newTokenPanel.setTokenValueComboBox(true, false, false, false); // Set to Auto Extract
											newTokenPanel.setGenericTextFieldText(finalExtractedValue);
										}
									}
								} catch (Exception e) {
									// Safe catch
								}
							});
						} else {
							// Token exists, update its value
							if (targetToken.getValue() == null || !targetToken.getValue().equals(extractedValue)) {
								targetToken.setValue(extractedValue);
							}
						}

						// Alert and update UI
						final com.protect7.authanalyzer.entities.Token finalToken = targetToken;
						final String finalValue = extractedValue;
						final boolean finalIsNewToken = isNewToken;
						BurpExtender.callbacks.issueAlert("[Live Proxy Sync] Session '" + session.getName() + "' updated token '" + finalToken.getName() + "'.");

						SwingUtilities.invokeLater(() -> {
							try {
								// Update stopped UI text field
								com.protect7.authanalyzer.gui.entity.SessionPanel sessionPanel = BurpExtender.mainPanel.getConfigurationPanel().getSessionPanelByName(session.getName());
								if (sessionPanel != null) {
									for (com.protect7.authanalyzer.gui.entity.TokenPanel tokenPanel : sessionPanel.getTokenPanelList()) {
										if (tokenPanel.getTokenName().equalsIgnoreCase(finalToken.getName())) {
											tokenPanel.setGenericTextFieldText(finalValue);
											break;
										}
									}
									// If it was newly created, re-initialize status panel so that the new token is rendered!
									if (finalIsNewToken && session.getStatusPanel() != null) {
										session.getStatusPanel().init(session);
									}
								}
								// Update running Status Panel
								if (session.getStatusPanel() != null) {
									session.getStatusPanel().updateTokenStatus(finalToken);
								}
							} catch (Exception e) {
								// Safe catch
							}
						});
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