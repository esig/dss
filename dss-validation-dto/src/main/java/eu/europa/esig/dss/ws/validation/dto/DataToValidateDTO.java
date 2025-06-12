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
package eu.europa.esig.dss.ws.validation.dto;

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.Collections;
import java.util.Date;
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
	 * <p>
	 * OPTIONAL.
	 */
	private List<RemoteDocument> originalDocuments;

	/**
	 * The custom validation policy to use
	 * <p>
	 * OPTIONAL.
	 */
	private RemoteDocument policy;

	/**
	 * The custom cryptographic suite to use
	 * <p>
	 * OPTIONAL.
	 */
	private RemoteDocument cryptographicSuite;

	/**
	 * Allows to specify a validation time different from the current time.
	 * <p>
	 * OPTIONAL.
	 */
	private Date validationTime;

	/**
	 * The detached evidence records applied to the signature file
	 * <p>
	 * OPTIONAL.
	 */
	private List<RemoteDocument> evidenceRecords;

	/**
	 * The strategy for the token (certificate/timestamp/revocation data) extraction
	 * <p>
	 * OPTIONAL.
	 */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/**
	 * The signature to operate on
	 * <p>
	 * OPTIONAL.
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
		this(signedDocument, Collections.singletonList(originalDocument), policy);
	}

	/**
	 * Constructor to validate a document
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocument {@link RemoteDocument} detached document
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy,
							 RemoteDocument cryptographicSuite) {
		this(signedDocument, Collections.singletonList(originalDocument), policy, cryptographicSuite);
	}

	/**
	 * Constructor to validate a document with validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocument {@link RemoteDocument} detached document
	 * @param validationTime {@link Date}
	 * @param policy {@link RemoteDocument} validation policy
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, Date validationTime, RemoteDocument policy) {
		this(signedDocument, Collections.singletonList(originalDocument), validationTime, policy);
	}

	/**
	 * Constructor to validate a document with validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocument {@link RemoteDocument} detached document
	 * @param validationTime {@link Date}
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, Date validationTime,
							 RemoteDocument policy, RemoteDocument cryptographicSuite) {
		this(signedDocument, Collections.singletonList(originalDocument), validationTime, policy, cryptographicSuite);
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
	 * Constructor to validate a document
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, RemoteDocument cryptographicSuite) {
		this(signedDocument, originalDocuments, policy, cryptographicSuite, Collections.emptyList(), null);
	}

	/**
	 * Constructor to validate a document with multiple detached files and validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param validationTime {@link Date}
	 * @param policy {@link RemoteDocument} validation policy
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 Date validationTime, RemoteDocument policy) {
		this(signedDocument, originalDocuments, validationTime, policy, Collections.emptyList(), null);
	}

	/**
	 * Constructor to validate a document with multiple detached files and validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param validationTime {@link Date}
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 Date validationTime, RemoteDocument policy, RemoteDocument cryptographicSuite) {
		this(signedDocument, originalDocuments, validationTime, policy, cryptographicSuite, Collections.emptyList(), null);
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
	 * Constructor to validate a document with applied evidence records
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param evidenceRecords list of {@link RemoteDocument} detached evidence records
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, RemoteDocument cryptographicSuite, List<RemoteDocument> evidenceRecords) {
		this(signedDocument, originalDocuments, policy, cryptographicSuite, evidenceRecords, null);
	}

	/**
	 * Constructor to validate a document with applied evidence records and validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param validationTime {@link Date} time to validate the document at
	 * @param policy {@link RemoteDocument} validation policy
	 * @param evidenceRecords list of {@link RemoteDocument} detached evidence records
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 Date validationTime, RemoteDocument policy, List<RemoteDocument> evidenceRecords) {
		this(signedDocument, originalDocuments, validationTime, policy, evidenceRecords, null);
	}

	/**
	 * Constructor to validate a document with applied evidence records and validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param validationTime {@link Date} time to validate the document at
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param evidenceRecords list of {@link RemoteDocument} detached evidence records
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 Date validationTime, RemoteDocument policy, RemoteDocument cryptographicSuite, List<RemoteDocument> evidenceRecords) {
		this(signedDocument, originalDocuments, validationTime, policy, cryptographicSuite, evidenceRecords, null);
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
		this(signedDocument, Collections.singletonList(originalDocument), policy, signatureId);
	}

	/**
	 * Constructor to extract original documents
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocument {@link RemoteDocument} detached document
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument,
							 RemoteDocument policy, RemoteDocument cryptographicSuite, String signatureId) {
		this(signedDocument, Collections.singletonList(originalDocument), policy, cryptographicSuite, signatureId);
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
	 * Constructor to extract original documents
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, RemoteDocument cryptographicSuite, String signatureId) {
		this(signedDocument, originalDocuments, policy, cryptographicSuite, Collections.emptyList(), signatureId);
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
		this(signedDocument, originalDocuments, (Date) null, policy, evidenceRecords, signatureId);
	}

	/**
	 * Constructor to extract original documents for validation with evidence records
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param evidenceRecords list of  {@link RemoteDocument} detached evidence records
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 RemoteDocument policy, RemoteDocument cryptographicSuite,
							 List<RemoteDocument> evidenceRecords, String signatureId) {
		this(signedDocument, originalDocuments, null, policy, cryptographicSuite, evidenceRecords, signatureId);
	}

	/**
	 * Constructor to extract original documents for validation with evidence records with validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param validationTime {@link Date} validation time
	 * @param policy {@link RemoteDocument} validation policy
	 * @param evidenceRecords list of  {@link RemoteDocument} detached evidence records
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 Date validationTime, RemoteDocument policy, List<RemoteDocument> evidenceRecords, String signatureId) {
		this(signedDocument, originalDocuments, validationTime, policy, null, evidenceRecords, signatureId);
	}

	/**
	 * Constructor to extract original documents for validation with evidence records with validation time
	 *
	 * @param signedDocument {@link RemoteDocument} to validate
	 * @param originalDocuments list of {@link RemoteDocument} detached documents
	 * @param validationTime {@link Date} validation time
	 * @param policy {@link RemoteDocument} validation policy
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param evidenceRecords list of  {@link RemoteDocument} detached evidence records
	 * @param signatureId {@link String} to extract original documents for
	 */
	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments,
							 Date validationTime, RemoteDocument policy, RemoteDocument cryptographicSuite,
							 List<RemoteDocument> evidenceRecords, String signatureId) {
		this.signedDocument = signedDocument;
		this.originalDocuments = originalDocuments;
		this.validationTime = validationTime;
		this.policy = policy;
		this.cryptographicSuite = cryptographicSuite;
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
	 * Gets a cryptographic suite document (to be applied globally)
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getCryptographicSuite() {
		return cryptographicSuite;
	}

	/**
	 * Sets a cryptographic suite document (to be applied globally)
	 *
	 * @param cryptographicSuite {@link RemoteDocument}
	 */
	public void setCryptographicSuite(RemoteDocument cryptographicSuite) {
		this.cryptographicSuite = cryptographicSuite;
	}

	/**
	 * Gets the validation time
	 *
	 * @return {@link Date}
	 */
	public Date getValidationTime() {
		return validationTime;
	}

	/**
	 * Sets the validation time
	 * NOTE: if not defined, the current time is used
	 *
	 * @param validationTime {@link Date}
	 */
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
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
