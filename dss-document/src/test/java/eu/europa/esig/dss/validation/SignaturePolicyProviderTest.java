package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.MemoryDataLoader;

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
