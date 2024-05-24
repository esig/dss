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

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.ProcessExecutorProvider;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * This is the interface to be used when implementing different signature validators.
 *
 */
public interface DocumentValidator extends ProcessExecutorProvider<DocumentProcessExecutor> {

	/**
	 * Retrieves the signatures found in the document
	 *
	 * @return a list of AdvancedSignatures for validation purposes
	 */
	List<AdvancedSignature> getSignatures();

	/**
	 * Retrieves the detached timestamps found in the document
	 *
	 * @return a list of TimestampToken for validation purposes
	 */
	List<TimestampToken> getDetachedTimestamps();

	/**
	 * Retrieves the detached evidence records found in the document
	 *
	 * @return a list of Evidence Records for validation purposes
	 */
	List<EvidenceRecord> getDetachedEvidenceRecords();

	/**
	 * Provides a {@code CertificateVerifier} to be used during the validation process.
	 *
	 * @param certVerifier
	 *            {@code CertificateVerifier}
	 */
	void setCertificateVerifier(final CertificateVerifier certVerifier);

	/**
	 * This method allows to set the token extraction strategy to follow in the
	 * diagnostic data generation.
	 * 
	 * @param tokenExtractionStrategy the {@link TokenExtractionStrategy}
	 */
	void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy);

	/**
	 * Sets the TokenIdentifierProvider
	 *
	 * @param tokenIdentifierProvider {@link TokenIdentifierProvider}
	 */
	void setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider);
	
	/**
	 * This method allows to enable/disable the semantics inclusion in the reports
	 * (Indication / SubIndication meanings)
	 * 
	 * Disabled by default
	 * 
	 * @param include true to enable the inclusion of the semantics
	 */
	void setIncludeSemantics(boolean include);

	/**
	 * Allows to define a custom validation time
	 * 
	 * @param validationTime {@link Date}
	 */
	void setValidationTime(Date validationTime);

	/**
	 * Sets the {@code List} of {@code DSSDocument} containing the original contents to sign, for detached signature
	 * scenarios.
	 *
	 * @param detachedContent
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setDetachedContents(final List<DSSDocument> detachedContent);

	/**
	 * Sets a {@code List} of {@code DSSDocument} containing the evidence record documents covering the signature document.
	 *
	 * @param detachedEvidenceRecordDocuments
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setDetachedEvidenceRecordDocuments(final List<DSSDocument> detachedEvidenceRecordDocuments);

	/**
	 * Sets the {@code List} of {@code DSSDocument} containing the original container content for ASiC-S signatures.
	 *
	 * @param archiveContents
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setContainerContents(final List<DSSDocument> archiveContents);

	/**
	 * Sets a related {@code ManifestFile} to the document to be validated.
	 *
	 * @param manifestFile
	 *            a {@code ManifestFile} to set
	 */
	void setManifestFile(final ManifestFile manifestFile);

	/**
	 * Set a certificate source which allows to find the signing certificate by kid
	 * or certificate's digest
	 * 
	 * @param certificateSource the certificate source
	 */
	void setSigningCertificateSource(CertificateSource certificateSource);

	/**
	 * This method allows to specify the validation level (Basic / Timestamp /
	 * Long Term / Archival). By default, the selected validation is ARCHIVAL
	 *
	 * @param validationLevel {@link ValidationLevel}
	 */
	void setValidationLevel(ValidationLevel validationLevel);
	
	/**
	 * This method allows to specify if the ETSI Validation Report must be generated.
	 * Default : TRUE (the ETSI Validation report will be generated).
	 * 
	 * @param enableEtsiValidationReport - TRUE if the report must be generated, FALSE otherwise
	 */
	void setEnableEtsiValidationReport(boolean enableEtsiValidationReport);
	
	/**
	 * This method allows to set a provider for Signature policies
	 * 
	 * @param signaturePolicyProvider {@link SignaturePolicyProvider}
	 */
	void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider);

	/**
	 * Validates the document and all its signatures. The default constraint file is used.
	 *
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument();

	/**
	 * Validates the document and all its signatures. If the validation policy URL is set then the policy constraints
	 * are retrieved from this location. If null or empty the
	 * default file is used.
	 *
	 * @param validationPolicyURL {@link URL}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final URL validationPolicyURL);

	/**
	 * Validates the document and all its signatures. The policyResourcePath specifies the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param policyResourcePath
	 *            is located against the classpath (getClass().getResourceAsStream), and NOT the filesystem
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final String policyResourcePath);

	/**
	 * Validates the document and all its signatures. The {@code File} parameter specifies the constraint file. If null
	 * or empty the default file is used.
	 *
	 * @param policyFile
	 *            contains the validation policy (xml) as {@code File}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final File policyFile);

	/**
	 * Validates the document and all its signatures. The policyDataStream contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param policyDocument
	 *            contains the validation policy (xml) as {@code DSSDocument}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final DSSDocument policyDocument);

	/**
	 * Validates the document and all its signatures. The policyDataStream contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param policyDataStream
	 *            contains the validation policy (xml) as {@code InputStream}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final InputStream policyDataStream);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicyJaxb} contains the constraint file. If
	 * null or empty the default file is used.
	 *
	 * @param validationPolicyJaxb
	 *            {@code ConstraintsParameters}
	 * @return {@link Reports}
	 */
	Reports validateDocument(final ConstraintsParameters validationPolicyJaxb);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicy} contains the constraint file. If null
	 * or empty the default file is used.
	 *
	 * @param validationPolicy
	 *            {@code ValidationPolicy}
	 * @return {@link Reports}
	 */
	Reports validateDocument(final ValidationPolicy validationPolicy);

	/**
	 * This method returns the signed document(s) without their signature(s)
	 *
	 * @param signatureId
	 *            the DSS ID of the signature to extract original signer data for
	 * @return list of {@link DSSDocument}s
	 */
	List<DSSDocument> getOriginalDocuments(final String signatureId);

	/**
	 * This method returns the signed document(s) without their signature(s)
	 *
	 * @param advancedSignature
	 *            {@link AdvancedSignature} to find signer documents for
	 * @return list of {@link DSSDocument}s
	 */
	List<DSSDocument> getOriginalDocuments(final AdvancedSignature advancedSignature);
	
	/**
	 * This method process the signature validation on the given {@code allSignatureList}
	 * 
	 * @param <T> {@link AdvancedSignature} implementation
	 * @param allSignatureList a collection of {@link AdvancedSignature}s to be validated
	 */
	<T extends AdvancedSignature> void processSignaturesValidation(Collection<T> allSignatureList);

	/**
	 * Extracts a validation data for provided collection of signatures
	 *
	 * @param <T> {@link AdvancedSignature} implementation
	 * @param signatures a collection of {@link AdvancedSignature}s
	 * @return {@link ValidationDataContainer}
	 */
	<T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures);

	/**
	 * Extracts a validation data for provided collection of signatures and/or timestamps
	 *
	 * @param <T> {@link AdvancedSignature} implementation
	 * @param signatures a collection of {@link AdvancedSignature}s
	 * @param detachedTimestamps a collection of detached {@link TimestampToken}s
	 * @return {@link ValidationDataContainer}
	 */
	<T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures, Collection<TimestampToken> detachedTimestamps);

}
