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
package eu.europa.esig.dss.ws.validation.dto;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

public class DataToValidateDTO {

	/**
	 * The document which contains the signature(s)
	 */
	private RemoteDocument signedDocument;

	/**
	 * The original file(s) in case of detached signature
	 */
	private List<RemoteDocument> originalDocuments;

	/**
	 * The custom validation policy to use
	 */
	private RemoteDocument policy;

	/**
	 * The strategy for the token (certificate/timestamp/revocation data) extraction
	 */
	private TokenExtractionStrategy tokenExtractionStategy = TokenExtractionStrategy.NONE;

	/**
	 * The signature to operate on
	 */
	private String signatureId;

	public DataToValidateDTO() {
	}

	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy) {
		this(signedDocument, Arrays.asList(originalDocument), policy);
	}

	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy) {
		this(signedDocument, originalDocuments, policy, null);
	}

	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy, String signatureId) {
		this(signedDocument, Arrays.asList(originalDocument), policy, signatureId);
	}

	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, String signatureId) {
		this.signedDocument = signedDocument;
		this.originalDocuments = originalDocuments;
		this.policy = policy;
		this.signatureId = signatureId;
	}

	public RemoteDocument getSignedDocument() {
		return signedDocument;
	}

	public void setSignedDocument(RemoteDocument signedDocument) {
		this.signedDocument = signedDocument;
	}

	public List<RemoteDocument> getOriginalDocuments() {
		return originalDocuments;
	}

	public void setOriginalDocuments(List<RemoteDocument> originalDocuments) {
		this.originalDocuments = originalDocuments;
	}

	public RemoteDocument getPolicy() {
		return policy;
	}

	public void setPolicy(RemoteDocument policy) {
		this.policy = policy;
	}

	public TokenExtractionStrategy getTokenExtractionStategy() {
		return tokenExtractionStategy;
	}

	public void setTokenExtractionStategy(TokenExtractionStrategy tokenExtractionStategy) {
		this.tokenExtractionStategy = tokenExtractionStategy;
	}

	public String getSignatureId() {
		return signatureId;
	}

	public void setSignatureId(String signatureId) {
		this.signatureId = signatureId;
	}

}
