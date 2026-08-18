package com.protect7.authanalyzer.controller;

import org.junit.Assert;
import org.junit.Test;

public class HttpListenerTest {

	@Test
	public void testIsHostMatchNullOrEmptyConfig() {
		// Empty or null config should match any request host
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", null));
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", ""));
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", "   "));
	}

	@Test
	public void testIsHostMatchExactDomain() {
		// Exact match for ns.example.com
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", "ns.example.com"));
		Assert.assertFalse(HttpListener.isHostMatch("dev.example.com", "ns.example.com"));
	}

	@Test
	public void testIsHostMatchCommaSeparatedDomains() {
		String config = "ns.example.com, dev.example.com";
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", config));
		Assert.assertTrue(HttpListener.isHostMatch("dev.example.com", config));
		Assert.assertFalse(HttpListener.isHostMatch("other.example.com", config));
	}

	@Test
	public void testIsHostMatchWildcardDomains() {
		String config = "*.example.com";
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", config));
		Assert.assertTrue(HttpListener.isHostMatch("dev.example.com", config));
		Assert.assertFalse(HttpListener.isHostMatch("example.org", config));
	}

	@Test
	public void testIsHostMatchCaseInsensitive() {
		Assert.assertTrue(HttpListener.isHostMatch("NS.EXAMPLE.COM", "ns.example.com"));
		Assert.assertTrue(HttpListener.isHostMatch("ns.example.com", "NS.EXAMPLE.COM"));
	}

	@Test
	public void testIsTriggerValueMatchNullOrEmptyConfig() {
		Assert.assertTrue(HttpListener.isTriggerValueMatch("Bearer eyJhbGci...", null));
		Assert.assertTrue(HttpListener.isTriggerValueMatch("Bearer eyJhbGci...", ""));
	}

	@Test
	public void testIsTriggerValueMatchExact() {
		Assert.assertTrue(HttpListener.isTriggerValueMatch("red", "red"));
		Assert.assertTrue(HttpListener.isTriggerValueMatch("RED", "red"));
		Assert.assertFalse(HttpListener.isTriggerValueMatch("red_light", "red"));
	}

	@Test
	public void testIsValueFilterMatchNullOrEmptyConfig() {
		Assert.assertTrue(HttpListener.isValueFilterMatch("Bearer eyJhbGci...", null));
		Assert.assertTrue(HttpListener.isValueFilterMatch("Bearer eyJhbGci...", ""));
	}

	@Test
	public void testIsValueFilterMatchPrefixAndSubstring() {
		Assert.assertTrue(HttpListener.isValueFilterMatch("Bearer eyJhbGci...", "Bearer"));
		Assert.assertTrue(HttpListener.isValueFilterMatch("Basic dXNlcjpwYXNz", "Basic"));
		Assert.assertFalse(HttpListener.isValueFilterMatch("Basic dXNlcjpwYXNz", "Bearer"));
	}
}
