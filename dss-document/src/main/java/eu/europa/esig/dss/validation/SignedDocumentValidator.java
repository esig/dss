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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.CustomProcessExecutor;
import eu.europa.esig.dss.validation.executor.ProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.revocation.crl.ListCRLSource;
import eu.europa.esig.dss.x509.revocation.ocsp.ListOCSPSource;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

/**
 * Validate the signed document. The content of the document is determined
 * automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 * SignatureScopeFinder can be set using the appropriate setter (ex.
 * setCadesSignatureScopeFinder). By default, this class will use the default
 * SignatureScopeFinder as defined by
 * eu.europa.esig.dss.validation.scope.SignatureScopeFinderFactory
 */
public abstract class SignedDocumentValidator implements DocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(SignedDocumentValidator.class);

	/**
	 * This variable can hold a specific {@code ProcessExecutor}
	 */
	protected ProcessExecutor processExecutor = null;

	/**
	 * This is the pool of certificates used in the validation process. The
	 * pools present in the certificate verifier are merged and added to this
	 * pool.
	 */
	protected CertificatePool validationCertPool = null;

	/**
	 * The document to validated (with the signature(s))
	 */
	protected DSSDocument document;

	/**
	 * In case of a detached signature this {@code List} contains the signed
	 * documents.
	 */
	protected List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();

	protected CertificateToken providedSigningCertificateToken = null;

	/**
	 * The reference to the certificate verifier. The current DSS implementation
	 * proposes {@link eu.europa.esig.dss.validation.CommonCertificateVerifier}.
	 * This verifier encapsulates the references to different sources used in
	 * the signature validation process.
	 */
	protected CertificateVerifier certificateVerifier;

	protected final SignatureScopeFinder signatureScopeFinder;

	protected SignaturePolicyProvider signaturePolicyProvider;

	// Default configuration with the highest level
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private static List<Class<SignedDocumentValidator>> registredDocumentValidators = new ArrayList<Class<SignedDocumentValidator>>();

	static {
		Properties properties = new Properties();
		try {
			properties.load(SignedDocumentValidator.class.getResourceAsStream("/document-validators.properties"));
		} catch (IOException e) {
			LOG.error("Cannot load properties from document-validators.properties : " + e.getMessage(), e);
		}
		for (String propName : properties.stringPropertyNames()) {
			registerDocumentValidator(propName, properties.getProperty(propName));
		}
	}

	private static void registerDocumentValidator(String type, String clazzToFind) {
		try {
			@SuppressWarnings("unchecked")
			Class<SignedDocumentValidator> documentValidator = (Class<SignedDocumentValidator>) Class.forName(clazzToFind);
			registredDocumentValidators.add(documentValidator);
			LOG.info("Validator '" + documentValidator.getName() + "' is registred");
		} catch (ClassNotFoundException e) {
			LOG.warn("Validator not found for signature type " + type);
		}
	}

	protected SignedDocumentValidator(SignatureScopeFinder signatureScopeFinder) {
		this.signatureScopeFinder = signatureScopeFinder;
	}

	/**
	 * This method guesses the document format and returns an appropriate
	 * document validator.
	 *
	 * @param dssDocument
	 *            The instance of {@code DSSDocument} to validate
	 * @return returns the specific instance of SignedDocumentValidator in terms
	 *         of the document type
	 */
	public static SignedDocumentValidator fromDocument(final DSSDocument dssDocument) {
		if (Utils.isCollectionEmpty(registredDocumentValidators)) {
			throw new DSSException("No validator registred");
		}

		for (Class<SignedDocumentValidator> clazz : registredDocumentValidators) {
			try {
				Constructor<SignedDocumentValidator> defaultAndPrivateConstructor = clazz.getDeclaredConstructor();
				defaultAndPrivateConstructor.setAccessible(true);
				SignedDocumentValidator validator = defaultAndPrivateConstructor.newInstance();
				if (validator.isSupported(dssDocument)) {
					Constructor<? extends SignedDocumentValidator> constructor = clazz.getDeclaredConstructor(DSSDocument.class);
					return constructor.newInstance(dssDocument);
				}
			} catch (Exception e) {
				LOG.error("Cannot instanciate class '" + clazz.getName() + "' : " + e.getMessage(), e);
			}
		}
		throw new DSSException("Document format not recognized/handled");
	}

	public abstract boolean isSupported(DSSDocument dssDocument);

	@Override
	public void defineSigningCertificate(final CertificateToken token) {
		if (token == null) {
			throw new NullPointerException("Token is not defined");
		}
		if (validationCertPool == null) {
			throw new NullPointerException("Certificate pool is not instantiated");
		}
		providedSigningCertificateToken = validationCertPool.getInstance(token, CertificateSourceType.OTHER);
	}

	/**
	 * To carry out the validation process of the signature(s) some external
	 * sources of certificates and of revocation data can be needed. The
	 * certificate verifier is used to pass these values. Note that once this
	 * setter is called any change in the content of the
	 * <code>CommonTrustedCertificateSource</code> or in adjunct certificate
	 * source is not taken into account.
	 *
	 * @param certificateVerifier
	 */
	@Override
	public void setCertificateVerifier(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
		if (validationCertPool == null) {
			validationCertPool = certificateVerifier.createValidationPool();
		}
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}

	/**
	 * This method allows to specify the validation level (Basic / Timestamp /
	 * Long Term / Archival). By default, the selected validation is ARCHIVAL
	 */
	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public Reports validateDocument() {
		return validateDocument((InputStream) null);
	}

	@Override
	public Reports validateDocument(final URL validationPolicyURL) {
		if (validationPolicyURL == null) {
			return validateDocument((InputStream) null);
		}
		try {
			return validateDocument(validationPolicyURL.openStream());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public Reports validateDocument(final String policyResourcePath) {
		if (policyResourcePath == null) {
			return validateDocument((InputStream) null);
		}
		return validateDocument(getClass().getResourceAsStream(policyResourcePath));
	}

	@Override
	public Reports validateDocument(final File policyFile) {
		if ((policyFile == null) || !policyFile.exists()) {
			return validateDocument((InputStream) null);
		}
		final InputStream inputStream = DSSUtils.toByteArrayInputStream(policyFile);
		return validateDocument(inputStream);
	}

	/**
	 * Validates the document and all its signatures. The policyDataStream
	 * contains the constraint file. If null or empty the default file is used.
	 *
	 * @param policyDataStream
	 *            the {@code InputStream} with the validation policy
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final InputStream policyDataStream) {
		final ConstraintsParameters validationPolicyJaxb = ValidationResourceManager.loadPolicyData(policyDataStream);
		return validateDocument(validationPolicyJaxb);
	}

	/**
	 * Validates the document and all its signatures. The
	 * {@code validationPolicyDom} contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param validationPolicyJaxb
	 *            the {@code ConstraintsParameters} to use in the validation process
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final ConstraintsParameters validationPolicyJaxb) {
		final ValidationPolicy validationPolicy = new EtsiValidationPolicy(validationPolicyJaxb);
		return validateDocument(validationPolicy);
	}

	/**
	 * Validates the document and all its signatures. The
	 * {@code validationPolicyDom} contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param validationPolicy
	 *            the {@code ValidationPolicy} to use in the validation process
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {
		LOG.info("Document validation...");
		if (certificateVerifier == null) {
			throw new NullPointerException("CertificateVerifier not defined");
		}

		ensureSignaturePolicyDetectorInitialized();

		boolean structuralValidation = isRequireStructuralValidation(validationPolicy);
		final ValidationContext validationContext = new SignatureValidationContext(validationCertPool);

		List<AdvancedSignature> allSignatureList = processSignaturesValidation(validationContext, structuralValidation);

		final DiagnosticData diagnosticData = new DiagnosticDataBuilder().document(document).containerInfo(getContainerInfo()).foundSignatures(allSignatureList)
				.usedCertificates(validationContext.getProcessedCertificates()).usedRevocations(validationContext.getProcessedRevocations())
				.includeRawCertificateTokens(certificateVerifier.isIncludeCertificateTokenValues())
				.includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
				.includeRawTimestampTokens(certificateVerifier.isIncludeTimestampTokenValues())
				.certificateSourceTypes(validationContext.getCertificateSourceTypes())
				.trustedCertificateSource(certificateVerifier.getTrustedCertSource())
				.validationDate(validationContext.getCurrentTime()).build();

		return processValidationPolicy(diagnosticData, validationPolicy);
	}

	@Override
	public List<AdvancedSignature> processSignaturesValidation(final ValidationContext validationContext, boolean structuralValidation) {
		final List<AdvancedSignature> allSignatureList = getAllSignatures();
		// The list of all signing certificates is created to allow a parallel
		// validation.
		prepareCertificatesAndTimestamps(allSignatureList, validationContext);

		final ListCRLSource signatureCRLSource = getSignatureCrlSource(allSignatureList);
		certificateVerifier.setSignatureCRLSource(signatureCRLSource);

		final ListOCSPSource signatureOCSPSource = getSignatureOcspSource(allSignatureList);
		certificateVerifier.setSignatureOCSPSource(signatureOCSPSource);

		validationContext.setCurrentTime(provideProcessExecutorInstance().getCurrentTime());
		validationContext.initialize(certificateVerifier);
		validationContext.validate();

		for (final AdvancedSignature signature : allSignatureList) {
			signature.checkSigningCertificate();
			signature.checkSignatureIntegrity();
			signature.validateTimestamps();
			if (structuralValidation) {
				signature.validateStructure();
			}
			signature.checkSignaturePolicy(signaturePolicyProvider);

			if (signatureScopeFinder != null) {
				signature.findSignatureScope(signatureScopeFinder);
			}
		}
		return allSignatureList;
	}

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return the container information
	 */
	protected ContainerInfo getContainerInfo() {
		return null;
	}

	protected Reports processValidationPolicy(DiagnosticData diagnosticData, ValidationPolicy validationPolicy) {
		final ProcessExecutor<Reports> executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setValidationLevel(validationLevel);
		executor.setDiagnosticData(diagnosticData);
		final Reports reports = executor.execute();
		return reports;
	}

	@Override
	public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
		this.signaturePolicyProvider = signaturePolicyProvider;
	}

	protected void ensureSignaturePolicyDetectorInitialized() {
		if (signaturePolicyProvider == null) {
			signaturePolicyProvider = new SignaturePolicyProvider();
			signaturePolicyProvider.setDataLoader(certificateVerifier.getDataLoader());
		}
	}

	@Override
	public void setProcessExecutor(final ProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}

	/**
	 * This method returns the process executor. If the instance of this class
	 * is not yet instantiated then the new instance is created.
	 *
	 * @return {@code ProcessExecutor}
	 */
	public ProcessExecutor<Reports> provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = new CustomProcessExecutor();
		}
		return processExecutor;
	}

	/**
	 * This method returns the list of all signatures including the
	 * countersignatures.
	 *
	 * @return {@code List} of {@code AdvancedSignature} to validate
	 */
	private List<AdvancedSignature> getAllSignatures() {
		final List<AdvancedSignature> allSignatureList = new ArrayList<AdvancedSignature>();
		List<AdvancedSignature> signatureList = getSignatures();
		for (final AdvancedSignature signature : signatureList) {
			allSignatureList.add(signature);
			allSignatureList.addAll(signature.getCounterSignatures());
		}
		return allSignatureList;
	}

	/**
	 * For all signatures to be validated this method merges the CRL sources.
	 *
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @return {@code ListCRLSource}
	 */
	private ListCRLSource getSignatureCrlSource(final List<AdvancedSignature> allSignatureList) {
		final ListCRLSource signatureCrlSource = new ListCRLSource();
		for (final AdvancedSignature signature : allSignatureList) {
			signatureCrlSource.addAll(signature.getCRLSource());
		}
		return signatureCrlSource;
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
	 *
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @return {@code ListOCSPSource}
	 */
	private ListOCSPSource getSignatureOcspSource(final List<AdvancedSignature> allSignatureList) {
		final ListOCSPSource signatureOcspSource = new ListOCSPSource();
		for (final AdvancedSignature signature : allSignatureList) {
			signatureOcspSource.addAll(signature.getOCSPSource());
		}
		return signatureOcspSource;
	}

	/**
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @param validationContext
	 *            {@code ValidationContext} is the implementation of the
	 *            validators for: certificates, timestamps and revocation data.
	 */
	private void prepareCertificatesAndTimestamps(final List<AdvancedSignature> allSignatureList, final ValidationContext validationContext) {
		for (final AdvancedSignature signature : allSignatureList) {
			final List<CertificateToken> candidates = signature.getCertificates();
			for (final CertificateToken certificateToken : candidates) {
				validationContext.addCertificateTokenForVerification(certificateToken);
			}
			signature.prepareTimestamps(validationContext);
		}
	}

	private boolean isRequireStructuralValidation(ValidationPolicy validationPolicy) {
		return ((validationPolicy != null) && (validationPolicy.getStructuralValidationConstraint(Context.SIGNATURE) != null));
	}

}
