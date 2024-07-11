/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SignaturePolicyProviderTest {

	private static final String POLICY_ID = "1.2.3";
	private static final String POLICY_URL = "http://localhost/my-policy.pdf";

	private static final DSSDocument POLICY_DOC = new InMemoryDocument(new byte[] { 1, 2, 3 });

	@Test
	void noPolicies() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		assertNull(spp.getSignaturePolicy(POLICY_ID, POLICY_URL));
		assertNull(spp.getSignaturePolicyByUrl(POLICY_URL));
		assertNull(spp.getSignaturePolicyById(POLICY_ID));
	}

	@Test
	void policyById() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesById = new HashMap<>();
		signaturePoliciesById.put(POLICY_ID, POLICY_DOC);
		spp.setSignaturePoliciesById(signaturePoliciesById);

		assertEquals(POLICY_DOC, spp.getSignaturePolicyById(POLICY_ID));
		assertEquals(POLICY_DOC, spp.getSignaturePolicy(POLICY_ID, null));
	}

	@Test
	void policyByUrl() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
		signaturePoliciesByUrl.put(POLICY_URL, POLICY_DOC);
		spp.setSignaturePoliciesByUrl(signaturePoliciesByUrl);

		assertEquals(POLICY_DOC, spp.getSignaturePolicyByUrl(POLICY_URL));
		assertEquals(POLICY_DOC, spp.getSignaturePolicy(POLICY_ID, POLICY_URL));
	}

	@Test
	void policyByDataLoader() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		Map<String, byte[]> dataMap = new HashMap<>();
		dataMap.put(POLICY_URL, new byte[] { 1, 2, 3 });
		DataLoader dataLoader = new MemoryDataLoader(dataMap);
		spp.setDataLoader(dataLoader);

		assertArrayEquals(POLICY_DOC.getDigestValue(DigestAlgorithm.SHA256), spp.getSignaturePolicyByUrl(POLICY_URL).getDigestValue(DigestAlgorithm.SHA256));
		assertArrayEquals(POLICY_DOC.getDigestValue(DigestAlgorithm.SHA256), spp.getSignaturePolicy(POLICY_ID, POLICY_URL).getDigestValue(DigestAlgorithm.SHA256));
	}

	@Test
	void policyUpdateTest() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();

		Map<String, byte[]> dataMap = new HashMap<>();
		byte[] policyContent = "Hello World!".getBytes(StandardCharsets.UTF_8);
		DSSDocument policy = new InMemoryDocument(policyContent);
		dataMap.put(POLICY_URL, policyContent);

		DataLoader dataLoader = new MemoryDataLoader(dataMap);
		spp.setDataLoader(dataLoader);

		assertArrayEquals(policy.getDigestValue(DigestAlgorithm.SHA256), spp.getSignaturePolicyByUrl(POLICY_URL).getDigestValue(DigestAlgorithm.SHA256));
		assertArrayEquals(policy.getDigestValue(DigestAlgorithm.SHA256), spp.getSignaturePolicy(POLICY_ID, POLICY_URL).getDigestValue(DigestAlgorithm.SHA256));

		policyContent = "Bye World!".getBytes(StandardCharsets.UTF_8);
		policy = new InMemoryDocument(policyContent);
		dataMap.put(POLICY_URL, policyContent);

		dataLoader = new MemoryDataLoader(dataMap);
		spp.setDataLoader(dataLoader);

		assertArrayEquals(policy.getDigestValue(DigestAlgorithm.SHA256), spp.getSignaturePolicyByUrl(POLICY_URL).getDigestValue(DigestAlgorithm.SHA256));
		assertArrayEquals(policy.getDigestValue(DigestAlgorithm.SHA256), spp.getSignaturePolicy(POLICY_ID, POLICY_URL).getDigestValue(DigestAlgorithm.SHA256));
	}

}
