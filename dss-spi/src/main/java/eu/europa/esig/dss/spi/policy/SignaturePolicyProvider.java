/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.policy;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * The class is used to retrieve a policy by its SignaturePolicyIdentifier
 *
 */
public class SignaturePolicyProvider {

	private static final Logger LOG = LoggerFactory.getLogger(SignaturePolicyProvider.class);

	/** The dataLoader to use to obtain a policy from a source (e.g. online) */
	private DataLoader dataLoader;

	/** Map of signature policy documents by IDs */
	private Map<String, DSSDocument> signaturePoliciesById = new HashMap<>();

	/** Map of signature policy documents by URLs */
	private Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();

	/**
	 * Default constructor instantiating object with null data loaded and empty maps
	 */
	public SignaturePolicyProvider() {
		// empty
	}

	/**
	 * Sets the {@code DataLoader} to retrieve signature policy documents (e.g. from online)
	 *
	 * @param dataLoader {@link DataLoader}
	 */
	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * Sets the map of signature policy documents to retrieve by IDs
	 *
	 * @param signaturePoliciesById a map of signature policy documents by IDs
	 */
	public void setSignaturePoliciesById(Map<String, DSSDocument> signaturePoliciesById) {
		this.signaturePoliciesById = signaturePoliciesById;
	}

	/**
	 * Sets the map of signature policy documents to retrieve by URLs
	 *
	 * @param signaturePoliciesByUrl a map of signature policy documents by URLs
	 */
	public void setSignaturePoliciesByUrl(Map<String, DSSDocument> signaturePoliciesByUrl) {
		this.signaturePoliciesByUrl = signaturePoliciesByUrl;
	}

	/**
	 * Gets a signature policy document with the corresponding {@code policyId} from {@code signaturePoliciesById} map
	 *
	 * @param policyId {@link String} id to retrieve a signaturePolicy with
	 * @return {@link DSSDocument} signature policy content if found, null otherwise
	 */
	public DSSDocument getSignaturePolicyById(String policyId) {
		return signaturePoliciesById.get(policyId);
	}

	/**
	 * Gets a signature policy document with the corresponding {@code url} from {@code signaturePoliciesByUrl} map,
	 * if not found, retrieved the data from {@code url} with {@code dataLoader}
	 *
	 * @param url {@link String} url to retrieve a signaturePolicy with
	 * @return {@link DSSDocument} signature policy content if found, null otherwise
	 */
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
			} catch (Exception e) {
				LOG.warn("Unable to download the signature policy with url '{}'", url, e);
			}
		}
		return dssDocument;
	}

	/**
	 * Gets signature policy by all available ways (id and uri)
	 *
	 * @param policyId {@link String} policy id
	 * @param url {@link String} policy url
	 * @return {@link DSSDocument} signature policy content if found, null otherwise
	 */
	public DSSDocument getSignaturePolicy(String policyId, String url) {
		DSSDocument dssDocument = getSignaturePolicyById(policyId);
		if (dssDocument == null) {
			dssDocument = getSignaturePolicyByUrl(url);
		}
		return dssDocument;
	}

}
