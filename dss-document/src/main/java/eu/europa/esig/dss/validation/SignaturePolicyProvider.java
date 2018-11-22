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
		if (dssDocument == null && Utils.isStringNotBlank(url) && dataLoader != null) {
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
			dssDocument = getSignaturePolicyByUrl(url);
			if (dssDocument != null) {
				signaturePoliciesById.put(policyId, dssDocument);
			}
		}
		return dssDocument;
	}

}
