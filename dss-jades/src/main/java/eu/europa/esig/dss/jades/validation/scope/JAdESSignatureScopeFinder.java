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
package eu.europa.esig.dss.jades.validation.scope;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.HTTPHeaderDigest;
import eu.europa.esig.dss.jades.HTTPHeaderMessageBodySignatureScope;
import eu.europa.esig.dss.jades.HTTPHeaderSignatureScope;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.signature.HttpHeadersPayloadBuilder;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class JAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<JAdESSignature> {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSignatureScopeFinder.class);

	@Override
	public List<SignatureScope> findSignatureScope(final JAdESSignature jadesSignature) {
		List<DSSDocument> originalDocuments = getOriginalDocuments(jadesSignature);
		return getSignatureScopeFromOriginalDocuments(originalDocuments);
	}

	/**
	 * Returns original documents for the given JAdES signature
	 * 
	 * @param jadesSignature {@link JAdESSignature} to get original document for
	 * @return a list of {@link DSSDocument}s original document
	 */
	protected List<DSSDocument> getOriginalDocuments(final JAdESSignature jadesSignature) {
		try {
			return jadesSignature.getOriginalDocuments();
		} catch (DSSException e) {
			LOG.warn("A JAdES signer's original document is not found [{}].", e.getMessage());
			return Collections.emptyList();
		}
	}

	protected List<SignatureScope> getSignatureScopeFromOriginalDocuments(List<DSSDocument> originalDocuments) {
		List<SignatureScope> result = new ArrayList<>();
		if (Utils.isCollectionEmpty(originalDocuments)) {
			return result;
		}
		
		for (DSSDocument originalDocument : originalDocuments) {
			String documentName = originalDocument.getName() != null ? originalDocument.getName() : "Detached content";
			if (originalDocument instanceof HTTPHeader) {
				// only http header documents shall be present
				return getHttpHeaderSignatureScope(originalDocuments);
				
			}
			else if (originalDocument instanceof DigestDocument) {
				DigestDocument digestDocument = (DigestDocument) originalDocument;
				result.add(new DigestSignatureScope(documentName, digestDocument.getExistingDigest()));
	
			} else {
				result.add(new FullSignatureScope(documentName,
						DSSUtils.getDigest(getDefaultDigestAlgorithm(), originalDocument)));
			}
		}

		return result;
	}
	
	private List<SignatureScope> getHttpHeaderSignatureScope(List<DSSDocument> originalDocuments) {
		List<SignatureScope> httpHeadersSignatureScopes = new ArrayList<>();
		
		HTTPHeader digestHttpHeader = null;
		
		List<HTTPHeader> httpHeaders = new ArrayList<>();
		for (DSSDocument document : originalDocuments) {
			if (document instanceof HTTPHeader) {
				httpHeaders.add((HTTPHeader) document);
				
				if (JAdESUtils.HTTP_HEADER_DIGEST.equals(document.getName())) {
					digestHttpHeader = (HTTPHeader) document;
				}
			}
		}
		SignatureScope httpHeadersPayloadSignatureScope = getHttpHeadersPayloadSignatureScope(httpHeaders);
		httpHeadersSignatureScopes.add(httpHeadersPayloadSignatureScope);
		
		if (digestHttpHeader != null) {
			SignatureScope httpHeaderDigestSignatureScope = getHttpHeaderDigestSignatureScope(digestHttpHeader);
			if (httpHeaderDigestSignatureScope != null) {
				httpHeadersSignatureScopes.add(httpHeaderDigestSignatureScope);
			}
		}
		
		return httpHeadersSignatureScopes;
	}
	
	private SignatureScope getHttpHeadersPayloadSignatureScope(List<HTTPHeader> httpHeaders) {
		HttpHeadersPayloadBuilder httpHeadersPayloadBuilder = new HttpHeadersPayloadBuilder(httpHeaders);
		byte[] payload = httpHeadersPayloadBuilder.build();
		byte[] digest = DSSUtils.digest(getDefaultDigestAlgorithm(), payload);
		return new HTTPHeaderSignatureScope(new Digest(getDefaultDigestAlgorithm(), digest));
	}
	
	private SignatureScope getHttpHeaderDigestSignatureScope(HTTPHeader digestHttpHeader) {
		Digest digest = getDigest(digestHttpHeader.getValue());
		if (digest != null) {
			if (digestHttpHeader instanceof HTTPHeaderDigest) {
				HTTPHeaderDigest httpHeaderDigest = (HTTPHeaderDigest) digestHttpHeader;
				return new HTTPHeaderMessageBodySignatureScope(httpHeaderDigest.getMessageBodyDocument().getName(), digest);
			} else {
				return new HTTPHeaderMessageBodySignatureScope(digest);
			}
		}
		return null;
	}
	
	private Digest getDigest(String digestHeaderValue) {
		String[] valueParts = digestHeaderValue.split("=");
		if (valueParts.length == 2) {
			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forJWSHttpHeader(valueParts[0]);
			byte[] digestValue = Utils.fromBase64(valueParts[1]);
			return new Digest(digestAlgorithm, digestValue);
		}
		LOG.warn("Not conformant value of 'Digest' header : '{}'!", digestHeaderValue);
		return null;
	}

}
