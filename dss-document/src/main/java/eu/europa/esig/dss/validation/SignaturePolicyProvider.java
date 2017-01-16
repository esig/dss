package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;

public class SignaturePolicyProvider {

	private static final Logger LOG = LoggerFactory.getLogger(SignaturePolicyProvider.class);

	private DataLoader dataLoader;

	private Map<String, DSSDocument> signaturePoliciesById = new HashMap<String, DSSDocument>();

	private Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();

	public DataLoader getDataLoader() {
		return dataLoader;
	}

	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	public Map<String, DSSDocument> getSignaturePoliciesById() {
		return signaturePoliciesById;
	}

	public void setSignaturePoliciesById(Map<String, DSSDocument> signaturePoliciesById) {
		this.signaturePoliciesById = signaturePoliciesById;
	}

	public DSSDocument getSignaturePolicyById(String policyId) {
		return signaturePoliciesById.get(policyId);
	}

	public Map<String, DSSDocument> getSignaturePoliciesByUrl() {
		return signaturePoliciesByUrl;
	}

	public void setSignaturePoliciesByUrl(Map<String, DSSDocument> signaturePoliciesByUrl) {
		this.signaturePoliciesByUrl = signaturePoliciesByUrl;
	}

	public DSSDocument getSignaturePolicyByUrl(String url) {
		DSSDocument dssDocument = signaturePoliciesByUrl.get(url);
		if (dssDocument == null && dataLoader != null) {
			try {
				byte[] bytes = dataLoader.get(url);
				if (Utils.isArrayEmpty(bytes)) {
					LOG.warn("Empty content for url '{}'", url);
					return null;
				}
				dssDocument = new InMemoryDocument(bytes);
				signaturePoliciesByUrl.put(url, dssDocument);
			} catch (Exception e) {
				LOG.warn("Unable to download the signature policy with url '{}'", url, e);
			}
		}
		return dssDocument;
	}

	public DSSDocument getSignaturePolicy(String policyId, String url) {
		DSSDocument dssDocument = getSignaturePolicyById(policyId);
		if (dssDocument == null) {
			dssDocument = getSignaturePolicyById(policyId);
		}
		return dssDocument;
	}

}
