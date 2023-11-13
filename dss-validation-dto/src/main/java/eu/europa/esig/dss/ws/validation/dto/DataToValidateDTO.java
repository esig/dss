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

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Represents a validation request DTO
 */
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
	 * The detached evidence records applied to the signature file
	 */
	private List<RemoteDocument> evidenceRecords;

	/**
	 * The strategy for the token (certificate/timestamp/revocation data) extraction
	 */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/**
	 * The signature to operate on
	 */
	private String signatureId;

	/**
	 * Empty constructor
	 */
	public DataToValidateDTO() {
		// empty
	}

	/**
	 * Constructor to validate a document
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocument {@link RemoteDocument} detached document
	 * @param policy {@link RemoteDocument} validation policy
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy) {
		this(signedDocument, Arrays.asList(originalDocument), policy);
	}

	/**
	 * Constructor to validate a document
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy) {
		this(signedDocument, originalDocuments, policy, Collections.emptyList(), null);
	}

	/**
	 * Constructor to validate a document with applied evidence records
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param evidenceRecords list of {@link RemoteDocument} detached evidence records
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, List<RemoteDocument> evidenceRecords) {
		this(signedDocument, originalDocuments, policy, evidenceRecords, null);
	}

	/**
	 * Constructor to extract original documents
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocument {@link RemoteDocument} detached document
	 * @param policy {@link RemoteDocument} validation policy
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument,
							 RemoteDocument policy, String signatureId) {
		this(signedDocument, Arrays.asList(originalDocument), policy, signatureId);
	}

	/**
	 * Constructor to extract original documents
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, String signatureId) {
		this(signedDocument, originalDocuments, policy, Collections.emptyList(), signatureId);
	}

	/**
	 * Constructor to extract original documents for validation with evidence records
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param evidenceRecords list of  {@link RemoteDocument} detached evidence records
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, List<RemoteDocument> evidenceRecords, String signatureId) {
		this.signedDocument = signedDocument;
		this.originalDocuments = originalDocuments;
		this.policy = policy;
		this.evidenceRecords = evidenceRecords;
		this.signatureId = signatureId;
	}

	/**
	 * Gets signed document
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getSignedDocument() {
		return signedDocument;
	}

	/**
	 * Sets the signed document
	 *
	 * @param signedDocument {@link RemoteDocument}
	 */
	public void setSignedDocument(RemoteDocument signedDocument) {
		this.signedDocument = signedDocument;
	}

	/**
	 * Gets the original (detached) documents
	 *
	 * @return a list of {@link RemoteDocument}s
	 */
	public List<RemoteDocument> getOriginalDocuments() {
		return originalDocuments;
	}

	/**
	 * Sets the original (detached) documents
	 *
	 * @param originalDocuments a list of {@link RemoteDocument}s
	 */
	public void setOriginalDocuments(List<RemoteDocument> originalDocuments) {
		this.originalDocuments = originalDocuments;
	}

	/**
	 * Gets the validation policy
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getPolicy() {
		return policy;
	}

	/**
	 * Sets the validation policy
	 *
	 * @param policy {@link RemoteDocument}
	 */
	public void setPolicy(RemoteDocument policy) {
		this.policy = policy;
	}

	/**
	 * Gets a list of detached evidence records
	 *
	 * @return a list of {@link RemoteDocument}s
	 */
	public List<RemoteDocument> getEvidenceRecords() {
		return evidenceRecords;
	}

	/**
	 * Sets a list of detached evidence records applied to the signature
	 *
	 * @param evidenceRecords a list of {@link RemoteDocument}s
	 */
	public void setEvidenceRecords(List<RemoteDocument> evidenceRecords) {
		this.evidenceRecords = evidenceRecords;
	}

	/**
	 * Gets a token extraction strategy
	 *
	 * @return {@link TokenExtractionStrategy}
	 */
	public TokenExtractionStrategy getTokenExtractionStrategy() {
		return tokenExtractionStrategy;
	}

	/**
	 * Sets a token extraction strategy
	 *
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy}
	 */
	public void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		this.tokenExtractionStrategy = tokenExtractionStrategy;
	}

	/**
	 * Gets the signature id to get original documents for
	 *
	 * @return {@link String}
	 */
	public String getSignatureId() {
		return signatureId;
	}

	/**
	 * Sets the signature id to get original documents for
	 *
	 * @param signatureId {@link String}
	 */
	public void setSignatureId(String signatureId) {
		this.signatureId = signatureId;
	}

}
