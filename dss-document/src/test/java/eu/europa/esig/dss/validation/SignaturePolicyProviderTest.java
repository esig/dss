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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;

public class SignaturePolicyProviderTest {

	private static final String POLICY_ID = "1.2.3";
	private static final String POLICY_URL = "http://localhost/my-policy.pdf";

	private DSSDocument policy = new InMemoryDocument(new byte[] { 1, 2, 3 });

	@Test
	public void noPolicies() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		assertNull(spp.getSignaturePolicy(POLICY_ID, POLICY_URL));
		assertNull(spp.getSignaturePolicyByUrl(POLICY_URL));
		assertNull(spp.getSignaturePolicyById(POLICY_ID));
	}

	@Test
	public void policyById() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesById = new HashMap<String, DSSDocument>();
		signaturePoliciesById.put(POLICY_ID, policy);
		spp.setSignaturePoliciesById(signaturePoliciesById);

		assertEquals(policy, spp.getSignaturePolicyById(POLICY_ID));
		assertEquals(policy, spp.getSignaturePolicy(POLICY_ID, null));
	}

	@Test
	public void policyByUrl() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();
		signaturePoliciesByUrl.put(POLICY_URL, policy);
		spp.setSignaturePoliciesByUrl(signaturePoliciesByUrl);

		assertEquals(policy, spp.getSignaturePolicyByUrl(POLICY_URL));
		assertEquals(policy, spp.getSignaturePolicy(POLICY_ID, POLICY_URL));
	}

	@Test
	public void policyByDataLoader() {
		SignaturePolicyProvider spp = new SignaturePolicyProvider();
		Map<String, byte[]> dataMap = new HashMap<String, byte[]>();
		dataMap.put(POLICY_URL, new byte[] { 1, 2, 3 });
		DataLoader dataLoader = new MemoryDataLoader(dataMap);
		spp.setDataLoader(dataLoader);

		assertEquals(policy.getDigest(DigestAlgorithm.SHA256), spp.getSignaturePolicyByUrl(POLICY_URL).getDigest(DigestAlgorithm.SHA256));
		assertEquals(policy.getDigest(DigestAlgorithm.SHA256), spp.getSignaturePolicy(POLICY_ID, POLICY_URL).getDigest(DigestAlgorithm.SHA256));
	}

}
