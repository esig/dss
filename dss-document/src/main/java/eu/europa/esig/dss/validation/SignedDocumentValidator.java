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
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlMessage;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureProductionPlace;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjects;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
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
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.ocsp.ListOCSPSource;
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

	private final SignatureScopeFinder signatureScopeFinder;

	/**
	 * This variable contains the reference to the diagnostic data.
	 */
	private DiagnosticData jaxbDiagnosticData; // JAXB object

	// Single policy document to use with all signatures.
	private File policyDocument;

	// Default configuration with the highest level
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private HashMap<String, File> policyDocuments;

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
	public DSSDocument getDocument() {
		return document;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return detachedContents;
	}

	@Override
	public void defineSigningCertificate(final CertificateToken token) {
		if (token == null) {
			throw new NullPointerException();
		}
		providedSigningCertificateToken = token;
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
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {

		this.detachedContents = detachedContents;
	}

	/**
	 * This method allows to provide an external policy document to be used with
	 * all signatures within the document to validate.
	 *
	 * @param policyDocument
	 */
	@Override
	public void setPolicyFile(final File policyDocument) {

		this.policyDocument = policyDocument;
	}

	/**
	 * This method allows to provide an external policy document to be used with
	 * a given signature id.
	 *
	 * @param signatureId
	 *            signature id
	 * @param policyDocument
	 */
	@Override
	public void setPolicyFile(final String signatureId, final File policyDocument) {

		if (policyDocuments == null) {

			policyDocuments = new HashMap<String, File>();
		}
		policyDocuments.put(signatureId, policyDocument);
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
	 *            {@code InputStream}
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
	 * @param validationPolicyDom
	 *            {@code Document}
	 * @return
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
	 *            {@code ValidationPolicy}
	 * @return
	 */
	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {
		LOG.info("Document validation...");
		if (certificateVerifier == null) {
			throw new NullPointerException();
		}

		ensureCertificatePoolInitialized();

		Date date1 = new Date();

		final ProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setValidationLevel(validationLevel);
		final DiagnosticData jaxbDiagnosticData = generateDiagnosticData();
		executor.setDiagnosticData(jaxbDiagnosticData);

		Date date2 = new Date();

		if (LOG.isTraceEnabled()) {
			final long dateDiff = DSSUtils.getDateDiff(date1, date2, TimeUnit.MILLISECONDS);
			LOG.trace("DiagnosticData building : " + dateDiff + " ms.");
		}

		final Reports reports = executor.execute();

		Date date3 = new Date();

		if (LOG.isTraceEnabled()) {
			final long dateDiff = DSSUtils.getDateDiff(date2, date3, TimeUnit.MILLISECONDS);
			LOG.trace("Reports building: " + dateDiff + " ms.");
		}

		return reports;
	}

	protected void ensureCertificatePoolInitialized() {
		if (validationCertPool == null) {
			if (certificateVerifier == null) {
				LOG.warn("No need of certificate pool ??");
				return;
			}
			Date start = new Date();
			validationCertPool = certificateVerifier.createValidationPool();
			if (providedSigningCertificateToken != null) {
				validationCertPool.getInstance(providedSigningCertificateToken, CertificateSourceType.OTHER);
			}
			Date end = new Date();
			if (LOG.isTraceEnabled()) {
				LOG.trace("CertificatePool building : {} ms.", DSSUtils.getDateDiff(start, end, TimeUnit.MILLISECONDS));
			}
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
	public ProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = new CustomProcessExecutor();
		}
		return processExecutor;
	}

	/**
	 * This method generates the diagnostic data. This is the set of all data
	 * extracted from the signature, associated certificates and trusted lists.
	 * The diagnostic data contains also the results of basic computations (hash
	 * check, signature integrity, certificates chain...
	 */
	private DiagnosticData generateDiagnosticData() {

		prepareDiagnosticData();

		final ValidationContext validationContext = new SignatureValidationContext(validationCertPool);

		final List<AdvancedSignature> allSignatureList = getAllSignatures();

		// The list of all signing certificates is created to allow a parallel
		// validation.
		prepareCertificatesAndTimestamps(allSignatureList, validationContext);

		final ListCRLSource signatureCRLSource = getSignatureCrlSource(allSignatureList);
		certificateVerifier.setSignatureCRLSource(signatureCRLSource);

		final ListOCSPSource signatureOCSPSource = getSignatureOcspSource(allSignatureList);
		certificateVerifier.setSignatureOCSPSource(signatureOCSPSource);

		validationContext.initialize(certificateVerifier);

		validationContext.setCurrentTime(provideProcessExecutorInstance().getCurrentTime());
		validationContext.validate();

		// For each validated signature present in the document to be validated
		// the extraction of diagnostic data is
		// launched.
		final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();
		for (final AdvancedSignature signature : allSignatureList) {

			final XmlSignature xmlSignature = validateSignature(signature);
			usedCertificatesDigestAlgorithms.addAll(signature.getUsedCertificatesDigestAlgorithms());
			jaxbDiagnosticData.getSignatures().add(xmlSignature);
		}
		final Set<CertificateToken> processedCertificates = validationContext.getProcessedCertificates();
		dealUsedCertificates(usedCertificatesDigestAlgorithms, processedCertificates);

		jaxbDiagnosticData.setValidationDate(validationContext.getCurrentTime());
		return jaxbDiagnosticData;
	}

	/**
	 * This method prepares the {@code DiagnosticData} object to store all
	 * static information about the signatures being validated.
	 */
	private void prepareDiagnosticData() {

		jaxbDiagnosticData = new DiagnosticData();

		String absolutePath = document.getAbsolutePath();
		String documentName = document.getName();
		if (Utils.isStringNotEmpty(absolutePath)) {
			jaxbDiagnosticData.setDocumentName(removeSpecialCharsForXml(absolutePath));
		} else if (Utils.isStringNotEmpty(documentName)) {
			jaxbDiagnosticData.setDocumentName(removeSpecialCharsForXml(documentName));
		} else {
			jaxbDiagnosticData.setDocumentName("?");
		}
	}

	/**
	 * Escape special characters which cause problems with jaxb or
	 * documentbuilderfactory and namespace aware mode
	 */
	private String removeSpecialCharsForXml(String text) {
		return text.replaceAll("&", "");
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
			final List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
			allSignatureList.addAll(counterSignatures);
		}
		return allSignatureList;
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
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

			final List<CertificateToken> candidates = signature.getCertificateSource().getCertificates();
			for (final CertificateToken certificateToken : candidates) {
				validationContext.addCertificateTokenForVerification(certificateToken);
			}
			signature.prepareTimestamps(validationContext);
		}
	}

	/**
	 * Main method for validating a signature. The diagnostic data is extracted.
	 *
	 * @param signature
	 *            Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @return The JAXB object containing all diagnostic data pertaining to the
	 *         signature
	 */
	private XmlSignature validateSignature(final AdvancedSignature signature) throws DSSException {

		final XmlSignature xmlSignature = new XmlSignature();
		try {

			final CertificateToken signingToken = dealSignature(signature, xmlSignature);

			dealPolicy(signature, xmlSignature);

			dealCertificateChain(xmlSignature, signingToken);

			signature.validateTimestamps();

			dealTimestamps(xmlSignature, signature.getContentTimestamps());

			dealTimestamps(xmlSignature, signature.getSignatureTimestamps());

			dealTimestamps(xmlSignature, signature.getTimestampsX1());

			dealTimestamps(xmlSignature, signature.getTimestampsX2());

			dealTimestamps(xmlSignature, signature.getArchiveTimestamps());

		} catch (Exception e) {

			// Any raised error is just logged and the process continues with
			// the next signature.
			LOG.warn(e.getMessage(), e);
			addErrorMessage(xmlSignature, e);
		}
		return xmlSignature;
	}

	private void addErrorMessage(final XmlSignature xmlSignature, final Exception e) {

		addErrorMessage(xmlSignature, e.toString());
	}

	private void addErrorMessage(final XmlSignature xmlSignature, final String message) {

		String currentMessage = message;
		String errorMessage = xmlSignature.getErrorMessage();
		if (Utils.isStringBlank(errorMessage)) {
			errorMessage = currentMessage;
		} else {
			errorMessage += "<br />" + currentMessage;
		}
		xmlSignature.setErrorMessage(errorMessage);
	}

	/**
	 * @param xmlSignature
	 * @param timestampTokens
	 */
	private void dealTimestamps(XmlSignature xmlSignature, final List<TimestampToken> timestampTokens) {
		if (Utils.isCollectionNotEmpty(timestampTokens)) {
			for (final TimestampToken timestampToken : timestampTokens) {
				xmlSignature.getTimestamps().add(xmlForTimestamp(timestampToken));
			}
		}
	}

	/**
	 * @param timestampToken
	 * @return
	 */
	private XmlTimestamp xmlForTimestamp(final TimestampToken timestampToken) {

		final XmlTimestamp xmlTimestampToken = new XmlTimestamp();
		xmlTimestampToken.setId(timestampToken.getDSSId().asXmlId());
		final TimestampType timestampType = timestampToken.getTimeStampType();
		xmlTimestampToken.setType(timestampType.name());
		xmlTimestampToken.setProductionTime(timestampToken.getGenerationTime());

		xmlTimestampToken.setSignedDataDigestAlgo(timestampToken.getSignedDataDigestAlgo().getName());
		xmlTimestampToken.setEncodedSignedDataDigestValue(timestampToken.getEncodedSignedDataDigestValue());
		xmlTimestampToken.setMessageImprintDataFound(timestampToken.isMessageImprintDataFound());
		xmlTimestampToken.setMessageImprintDataIntact(timestampToken.isMessageImprintDataIntact());
		xmlTimestampToken.setCanonicalizationMethod(timestampToken.getCanonicalizationMethod());

		final SignatureAlgorithm signatureAlgorithm = timestampToken.getSignatureAlgorithm();
		final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();
		if (signatureAlgorithm != null) {

			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm().getName());
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm().getName());
		}
		final String keyLength = DSSPKUtils.getPublicKeySize(timestampToken);
		xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);

		final boolean signatureValid = timestampToken.isSignatureValid();
		xmlBasicSignatureType.setReferenceDataFound(signatureValid /* timestampToken.isReferenceDataFound() */);
		xmlBasicSignatureType.setReferenceDataIntact(signatureValid /* timestampToken.isReferenceDataIntact() */);
		xmlBasicSignatureType.setSignatureIntact(signatureValid /* timestampToken.isSignatureIntact() */);
		xmlBasicSignatureType.setSignatureValid(signatureValid);
		xmlTimestampToken.setBasicSignature(xmlBasicSignatureType);

		final CertificateToken issuerToken = timestampToken.getIssuerToken();

		XmlSigningCertificate xmlTSSignCert = xmlForSigningCertificate(issuerToken);
		xmlTimestampToken.setSigningCertificate(xmlTSSignCert);

		final List<XmlChainItem> xmlCertChainType = xmlForCertificateChain(issuerToken);
		xmlTimestampToken.setCertificateChain(xmlCertChainType);

		final List<TimestampReference> timestampReferences = timestampToken.getTimestampedReferences();
		if (Utils.isCollectionNotEmpty(timestampReferences)) {
			final XmlSignedObjects xmlSignedObjectsType = new XmlSignedObjects();
			final List<XmlDigestAlgoAndValue> xmlDigestAlgAndValueList = xmlSignedObjectsType.getDigestAlgoAndValues();

			for (final TimestampReference timestampReference : timestampReferences) {

				final TimestampReferenceCategory timestampedCategory = timestampReference.getCategory();
				if (TimestampReferenceCategory.SIGNATURE.equals(timestampedCategory)) {

					final XmlSignedSignature xmlSignedSignature = new XmlSignedSignature();
					xmlSignedSignature.setId(timestampReference.getSignatureId());
					xmlSignedObjectsType.getSignedSignature().add(xmlSignedSignature);
				} else if (TimestampReferenceCategory.TIMESTAMP.equals(timestampedCategory)) {
					final XmlTimestampedTimestamp xmlTimestampedTimestamp = new XmlTimestampedTimestamp();
					xmlTimestampedTimestamp.setId(timestampReference.getSignatureId());
					xmlSignedObjectsType.getTimestampedTimestamp().add(xmlTimestampedTimestamp);
				} else {

					final XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
					xmlDigestAlgAndValue.setDigestMethod(timestampReference.getDigestAlgorithm().getName());
					xmlDigestAlgAndValue.setDigestValue(timestampReference.getDigestValue());
					xmlDigestAlgAndValue.setCategory(timestampedCategory.name());
					xmlDigestAlgAndValueList.add(xmlDigestAlgAndValue);
				}
			}
			xmlTimestampToken.setSignedObjects(xmlSignedObjectsType);
		}
		return xmlTimestampToken;
	}

	/**
	 * @param issuerToken
	 * @return
	 */
	private List<XmlChainItem> xmlForCertificateChain(final CertificateToken issuerToken) {

		if (issuerToken != null) {

			CertificateToken issuerToken_ = issuerToken;
			final List<XmlChainItem> certChainTokens = new ArrayList<XmlChainItem>();
			do {

				final XmlChainItem xmlCertToken = new XmlChainItem();
				xmlCertToken.setId(issuerToken_.getDSSId().asXmlId());
				final CertificateSourceType mainSource = getCertificateMainSourceType(issuerToken_);
				xmlCertToken.setSource(mainSource.name());
				certChainTokens.add(xmlCertToken);
				if (issuerToken_.isTrusted() || issuerToken_.isSelfSigned()) {

					break;
				}
				issuerToken_ = issuerToken_.getIssuerToken();
			} while (issuerToken_ != null);
			return certChainTokens;
		}
		return null;
	}

	private CertificateSourceType getCertificateMainSourceType(final CertificateToken issuerToken) {
		CertificateSourceType mainSource = CertificateSourceType.UNKNOWN;
		final Set<CertificateSourceType> sourceList = issuerToken.getSources();
		if (sourceList.size() > 0) {
			if (sourceList.contains(CertificateSourceType.TRUSTED_LIST)) {
				mainSource = CertificateSourceType.TRUSTED_LIST;
			} else if (sourceList.contains(CertificateSourceType.TRUSTED_STORE)) {
				mainSource = CertificateSourceType.TRUSTED_STORE;
			} else {
				mainSource = sourceList.iterator().next();
			}
		}
		return mainSource;
	}

	/**
	 * @param usedCertificatesDigestAlgorithms
	 * @param usedCertTokens
	 */
	private void dealUsedCertificates(final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms, final Set<CertificateToken> usedCertTokens) {
		for (final CertificateToken certToken : usedCertTokens) {
			final XmlCertificate xmlCert = dealCertificateDetails(usedCertificatesDigestAlgorithms, certToken);
			// !!! Log the certificate
			if (LOG.isTraceEnabled()) {
				LOG.trace("PEM for certificate: " + certToken.getAbbreviation() + "--->");
				final String pem = DSSUtils.convertToPEM(certToken);
				LOG.trace("\n" + pem);
			}
			dealTrustedService(certToken, xmlCert);
			dealRevocationData(usedCertificatesDigestAlgorithms, certToken, xmlCert);
			dealCertificateValidationInfo(certToken, xmlCert);
			jaxbDiagnosticData.getUsedCertificates().add(xmlCert);
		}
	}

	/**
	 * This method deals with the certificate validation extra information. The
	 * retrieved information is transformed to the JAXB object.
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealCertificateValidationInfo(final CertificateToken certToken, final XmlCertificate xmlCert) {
		final List<String> list = certToken.getValidationInfo();
		if (Utils.isCollectionNotEmpty(list)) {
			int i = 0;
			for (String message : list) {
				final XmlMessage xmlMessage = new XmlMessage();
				xmlMessage.setId(i);
				xmlMessage.setValue(message);
				xmlCert.getInfo().add(xmlMessage);
				i++;
			}
		}
	}

	/**
	 * This method deals with the certificate's details. The retrieved
	 * information is transformed to the JAXB object.
	 *
	 * @param usedDigestAlgorithms
	 *            set of different digest algorithms used to compute certificate
	 *            digest
	 * @param certToken
	 *            current certificate token
	 * @return
	 */
	private XmlCertificate dealCertificateDetails(final Set<DigestAlgorithm> usedDigestAlgorithms, final CertificateToken certToken) {

		final XmlCertificate xmlCert = new XmlCertificate();

		xmlCert.setId(certToken.getDSSId().asXmlId());

		XmlDistinguishedName xmlDistinguishedName = xmlForDistinguishedName(X500Principal.CANONICAL, certToken.getSubjectX500Principal());
		xmlCert.getSubjectDistinguishedName().add(xmlDistinguishedName);
		xmlDistinguishedName = xmlForDistinguishedName(X500Principal.RFC2253, certToken.getSubjectX500Principal());
		xmlCert.getSubjectDistinguishedName().add(xmlDistinguishedName);

		xmlDistinguishedName = xmlForDistinguishedName(X500Principal.CANONICAL, certToken.getIssuerX500Principal());
		xmlCert.getIssuerDistinguishedName().add(xmlDistinguishedName);
		xmlDistinguishedName = xmlForDistinguishedName(X500Principal.RFC2253, certToken.getIssuerX500Principal());
		xmlCert.getIssuerDistinguishedName().add(xmlDistinguishedName);

		xmlCert.setSerialNumber(certToken.getSerialNumber());
		X500Principal x500Principal = certToken.getSubjectX500Principal();
		xmlCert.setCommonName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, x500Principal));
		xmlCert.setCountryName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, x500Principal));
		xmlCert.setOrganizationName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, x500Principal));
		xmlCert.setGivenName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.GIVENNAME, x500Principal));
		xmlCert.setOrganizationalUnit(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.OU, x500Principal));
		xmlCert.setSurname(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.SURNAME, x500Principal));
		xmlCert.setPseudonym(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.PSEUDONYM, x500Principal));

		for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {

			final XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
			xmlDigestAlgAndValue.setDigestMethod(digestAlgorithm.getName());
			xmlDigestAlgAndValue.setDigestValue(DSSUtils.digest(digestAlgorithm, certToken));
			xmlCert.getDigestAlgoAndValues().add(xmlDigestAlgAndValue);
		}
		xmlCert.setNotAfter(certToken.getNotAfter());
		xmlCert.setNotBefore(certToken.getNotBefore());
		final PublicKey publicKey = certToken.getPublicKey();
		xmlCert.setPublicKeySize(DSSPKUtils.getPublicKeySize(publicKey));
		xmlCert.setPublicKeyEncryptionAlgo(DSSPKUtils.getPublicKeyEncryptionAlgo(publicKey));

		xmlForKeyUsageBits(certToken, xmlCert);

		if (DSSASN1Utils.isOCSPSigning(certToken)) {
			xmlCert.setIdKpOCSPSigning(true);
		}
		if (DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken)) {
			xmlCert.setIdPkixOcspNoCheck(true);
		}

		final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();

		final SignatureAlgorithm signatureAlgorithm = certToken.getSignatureAlgorithm();
		xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm().getName());
		xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm().getName());
		final String keyLength = DSSPKUtils.getPublicKeySize(certToken);
		xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);
		final boolean signatureIntact = certToken.isSignatureValid();
		xmlBasicSignatureType.setReferenceDataFound(signatureIntact);
		xmlBasicSignatureType.setReferenceDataIntact(signatureIntact);
		xmlBasicSignatureType.setSignatureIntact(signatureIntact);
		xmlBasicSignatureType.setSignatureValid(signatureIntact);
		xmlCert.setBasicSignature(xmlBasicSignatureType);

		final CertificateToken issuerToken = certToken.getIssuerToken();
		xmlCert.setSigningCertificate(xmlForSigningCertificate(issuerToken));
		xmlCert.setCertificateChain(xmlForCertificateChain(issuerToken));

		List<String> qcStatementsIdList = DSSASN1Utils.getQCStatementsIdList(certToken);
		if (Utils.isCollectionNotEmpty(qcStatementsIdList)) {
			xmlCert.setQCStatementIds(qcStatementsIdList);
		}

		final List<String> qcTypesIdList = DSSASN1Utils.getQCTypesIdList(certToken);
		if (Utils.isCollectionNotEmpty(qcTypesIdList)) {
			xmlCert.setQCTypes(qcTypesIdList);
		}
		
		List<String> policyIdentifiersList = DSSASN1Utils.getPolicyIdentifiers(certToken);
		if (Utils.isCollectionNotEmpty(policyIdentifiersList)) {
			xmlCert.setCertificatePolicyIds(policyIdentifiersList);
		}

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(certToken.isTrusted());

		return xmlCert;
	}

	private void xmlForKeyUsageBits(CertificateToken certToken, XmlCertificate xmlCert) {
		final Set<KeyUsageBit> keyUsageBits = certToken.getKeyUsageBits();
		if (Utils.isCollectionEmpty(keyUsageBits)) {
			return;
		}
		final List<String> xmlKeyUsageBitItems = new ArrayList<String>();
		for (final KeyUsageBit keyUsageBit : keyUsageBits) {
			xmlKeyUsageBitItems.add(keyUsageBit.name());
		}
		xmlCert.setKeyUsageBits(xmlKeyUsageBitItems);
	}

	private XmlDistinguishedName xmlForDistinguishedName(final String x500PrincipalFormat, final X500Principal X500PrincipalName) {

		final XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat(x500PrincipalFormat);
		final String x500PrincipalName = X500PrincipalName.getName(x500PrincipalFormat);
		xmlDistinguishedName.setValue(x500PrincipalName);
		return xmlDistinguishedName;
	}

	/**
	 * This method deals with the certificate chain. The retrieved information
	 * is transformed to the JAXB object.
	 *
	 * @param xmlSignature
	 *            The JAXB object containing all diagnostic data pertaining to
	 *            the signature
	 * @param signingToken
	 *            {@code CertificateToken} relative to the current signature
	 */
	private void dealCertificateChain(final XmlSignature xmlSignature, final CertificateToken signingToken) {
		if (signingToken != null) {
			xmlSignature.setCertificateChain(xmlForCertificateChain(signingToken));
		}
	}

	/**
	 * This method deals with the trusted service information in case of trusted
	 * certificate. The retrieved information is transformed to the JAXB object.
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealTrustedService(final CertificateToken certToken, final XmlCertificate xmlCert) {
		Set<ServiceInfo> services = null;
		if (certToken.isTrusted()) {
			services = certToken.getAssociatedTSPS();
		} else {
			final CertificateToken trustAnchor = certToken.getTrustAnchor();
			if (trustAnchor == null) {
				return;
			}
			services = trustAnchor.getAssociatedTSPS();
		}
		if (Utils.isCollectionNotEmpty(services)) {
			for (final ServiceInfo serviceInfo : services) {
				final XmlTrustedServiceProvider xmlTSP = new XmlTrustedServiceProvider();
				xmlTSP.setTSPName(serviceInfo.getTspName());
				xmlTSP.setTSPServiceName(serviceInfo.getServiceName());
				xmlTSP.setTSPServiceType(serviceInfo.getType());
				xmlTSP.setWellSigned(serviceInfo.isTlWellSigned());

				final ServiceInfoStatus serviceStatusAtCertIssuance = serviceInfo.getStatus().getCurrent(certToken.getNotBefore());
				if (serviceStatusAtCertIssuance != null) {

					xmlTSP.setStatus(serviceStatusAtCertIssuance.getStatus());
					xmlTSP.setStartDate(serviceStatusAtCertIssuance.getStartDate());
					xmlTSP.setEndDate(serviceStatusAtCertIssuance.getEndDate());

					// Check of the associated conditions to identify the qualifiers
					final List<String> qualifiers = getQualifiers(serviceStatusAtCertIssuance, certToken);
					if (Utils.isCollectionNotEmpty(qualifiers)) {
						xmlTSP.setQualifiers(qualifiers);
					}

					List<String> additionalServiceInfoUris = serviceStatusAtCertIssuance.getAdditionalServiceInfoUris();
					if (Utils.isCollectionNotEmpty(additionalServiceInfoUris)) {
						xmlTSP.setAdditionalServiceInfoUris(additionalServiceInfoUris);
					}

					xmlTSP.setExpiredCertsRevocationInfo(serviceStatusAtCertIssuance.getExpiredCertsRevocationInfo());
				}
				xmlCert.getTrustedServiceProvider().add(xmlTSP);
			}
		}
	}

	/**
	 * Retrieves all the qualifiers for which the corresponding conditionEntry
	 * is true.
	 *
	 * @param certificateToken
	 * @return
	 */
	public List<String> getQualifiers(ServiceInfoStatus serviceStatusAtCertIssuance, CertificateToken certificateToken) {
		LOG.trace("--> GET_QUALIFIERS()");
		List<String> list = new ArrayList<String>();
		final Map<String, List<Condition>> qualifiersAndConditions = serviceStatusAtCertIssuance.getQualifiersAndConditions();
		for (Entry<String, List<Condition>> conditionEntry : qualifiersAndConditions.entrySet()) {
			List<Condition> conditions = conditionEntry.getValue();
			LOG.trace("  --> " + conditions);
			for (final Condition condition : conditions) {
				if (condition.check(certificateToken)) {
					LOG.trace("    --> CONDITION TRUE / " + conditionEntry.getKey());
					list.add(conditionEntry.getKey());
					break;
				}
			}
		}
		return list;

	}

	/**
	 * This method deals with the revocation data of a certificate. The
	 * retrieved information is transformed to the JAXB object.
	 * 
	 * @param usedCertificatesDigestAlgorithms
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private void dealRevocationData(Set<DigestAlgorithm> usedDigestAlgorithms, final CertificateToken certToken, final XmlCertificate xmlCert) {
		final Set<RevocationToken> revocationTokens = certToken.getRevocationTokens();
		if (Utils.isCollectionNotEmpty(revocationTokens)) {
			for (RevocationToken revocationToken : revocationTokens) {
				final XmlRevocation xmlRevocation = new XmlRevocation();
				xmlRevocation.setOrigin(revocationToken.getOrigin().name());
				final Boolean revocationTokenStatus = revocationToken.getStatus();
				// revocationTokenStatus can be null when OCSP return Unknown. In
				// this case we set status to false.
				xmlRevocation.setStatus(revocationTokenStatus == null ? false : revocationTokenStatus);
				xmlRevocation.setProductionDate(revocationToken.getProductionDate());
				xmlRevocation.setThisUpdate(revocationToken.getThisUpdate());
				xmlRevocation.setNextUpdate(revocationToken.getNextUpdate());
				xmlRevocation.setRevocationDate(revocationToken.getRevocationDate());
				xmlRevocation.setExpiredCertsOnCRL(revocationToken.getExpiredCertsOnCRL());
				xmlRevocation.setArchiveCutOff(revocationToken.getArchiveCutOff());
				xmlRevocation.setReason(revocationToken.getReason());
				xmlRevocation.setSource(revocationToken.getClass().getSimpleName());

				String sourceURL = revocationToken.getSourceURL();
				if (Utils.isStringNotEmpty(sourceURL)) { // not empty = online
					xmlRevocation.setSourceAddress(sourceURL);
					xmlRevocation.setAvailable(revocationToken.isAvailable());
				}

				// In case of CRL, the X509CRL can be the same for different
				// certificates
				byte[] digestForId = DSSUtils.digest(DigestAlgorithm.SHA256, certToken.getEncoded(), revocationToken.getEncoded());
				xmlRevocation.setId(DatatypeConverter.printHexBinary(digestForId));

				final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();
				final SignatureAlgorithm revocationSignatureAlgo = revocationToken.getSignatureAlgorithm();
				final boolean unknownAlgorithm = revocationSignatureAlgo == null;
				final String encryptionAlgorithmName = unknownAlgorithm ? "?" : revocationSignatureAlgo.getEncryptionAlgorithm().getName();
				xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmName);
				final String keyLength = DSSPKUtils.getPublicKeySize(revocationToken);
				xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(keyLength);

				final String digestAlgorithmName = unknownAlgorithm ? "?" : revocationSignatureAlgo.getDigestAlgorithm().getName();
				xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(digestAlgorithmName);
				final boolean signatureValid = revocationToken.isSignatureValid();
				xmlBasicSignatureType.setReferenceDataFound(signatureValid);
				xmlBasicSignatureType.setReferenceDataIntact(signatureValid);
				xmlBasicSignatureType.setSignatureIntact(signatureValid);
				xmlBasicSignatureType.setSignatureValid(signatureValid);
				xmlRevocation.setBasicSignature(xmlBasicSignatureType);

				for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {
					final XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
					xmlDigestAlgAndValue.setDigestMethod(digestAlgorithm.getName());
					xmlDigestAlgAndValue.setDigestValue(DSSUtils.digest(digestAlgorithm, revocationToken));
					xmlRevocation.getDigestAlgoAndValues().add(xmlDigestAlgAndValue);
				}

				final CertificateToken issuerToken = revocationToken.getIssuerToken();
				final XmlSigningCertificate xmlRevocationSignCert = xmlForSigningCertificate(issuerToken);
				xmlRevocation.setSigningCertificate(xmlRevocationSignCert);
				xmlRevocation.setCertificateChain(xmlForCertificateChain(issuerToken));

				final List<String> list = revocationToken.getValidationInfo();

				if (Utils.isCollectionNotEmpty(list)) {
					int i = 0;
					for (String message : list) {
						final XmlMessage xmlMessage = new XmlMessage();
						xmlMessage.setId(i);
						xmlMessage.setValue(message);
						xmlRevocation.getInfo().add(xmlMessage);
						i++;
					}
				}
				xmlCert.getRevocation().add(xmlRevocation);
			}
		}
	}

	/**
	 * This method deals with the signature policy. The retrieved information is
	 * transformed to the JAXB object.
	 *
	 * @param signature
	 *            Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature
	 *            The JAXB object containing all diagnostic data pertaining to
	 *            the signature
	 */
	private void dealPolicy(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		SignaturePolicy signaturePolicy = null;
		try {
			signaturePolicy = signature.getPolicyId();
		} catch (Exception e) {
			final String msg = "Error when extracting the signature policy: " + e.getMessage();
			LOG.warn(msg, e);
			addErrorMessage(xmlSignature, msg);
		}
		if (signaturePolicy == null) {
			return;
		}

		final XmlPolicy xmlPolicy = new XmlPolicy();
		xmlSignature.setPolicy(xmlPolicy);

		final String policyId = signaturePolicy.getIdentifier();
		xmlPolicy.setId(policyId);

		final String policyUrl = signaturePolicy.getUrl();
		xmlPolicy.setUrl(policyUrl);

		final String notice = signaturePolicy.getNotice();
		xmlPolicy.setNotice(notice);

		final byte[] digestValue = signaturePolicy.getDigestValue();
		final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();

		if (Utils.isArrayNotEmpty(digestValue)) {
			XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
			xmlDigestAlgAndValue.setDigestMethod(signPolicyHashAlgFromSignature == null ? "" : signPolicyHashAlgFromSignature.getName());
			xmlDigestAlgAndValue.setDigestValue(DatatypeConverter.printBase64Binary(digestValue));
			xmlPolicy.setDigestAlgoAndValue(xmlDigestAlgAndValue);
		}

		/**
		 * ETSI 102 853: 3) Obtain the digest of the resulting document against
		 * which the digest value present in the property/attribute will be
		 * checked:
		 */
		if ((policyDocument == null) && Utils.isStringEmpty(policyUrl)) {
			xmlPolicy.setIdentified(false);
			if (policyId.isEmpty()) {
				xmlPolicy.setStatus(true);
			} else {
				xmlPolicy.setStatus(false);
			}
			return;
		}
		xmlPolicy.setIdentified(true);

		byte[] policyBytes = null;
		try {
			if (policyDocument == null) {
				final DataLoader dataLoader = certificateVerifier.getDataLoader();
				policyBytes = dataLoader.get(policyUrl);
			} else {
				policyBytes = DSSUtils.toByteArray(policyDocument);
			}
		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.getMessage());
			// Do nothing
			LOG.warn(e.getMessage(), e);
			return;
		}

		if (Utils.isArrayEmpty(policyBytes)) {
			xmlPolicy.setIdentified(false);
			xmlPolicy.setProcessingError("Empty content for policy");
			return;
		}

		ASN1Sequence asn1Sequence = null;
		try {
			asn1Sequence = DSSASN1Utils.toASN1Primitive(policyBytes);
		} catch (Exception e) {
			LOG.info("Policy bytes are not asn1 processable : " + e.getMessage());
		}

		try {
			if (asn1Sequence != null) {
				xmlPolicy.setAsn1Processable(true);

				/**
				 * a) If the resulting document is based on TR 102 272 [i.2]
				 * (ESI: ASN.1 format for signature policies), use the digest
				 * value present in the SignPolicyDigest element from the
				 * resulting document. Check that the digest algorithm indicated
				 * in the SignPolicyDigestAlg from the resulting document is
				 * equal to the digest algorithm indicated in the property.
				 */

				final ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Sequence.getObjectAt(0);
				final AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
				DigestAlgorithm signPolicyHashAlgFromPolicy = DigestAlgorithm.forOID(signPolicyHashAlgIdentifier.getAlgorithm().getId());

				/**
				 * b) If the resulting document is based on TR 102 038 [i.3]
				 * ((ESI) XML format for signature policies), use the digest
				 * value present in signPolicyHash element from the resulting
				 * document. Check that the digest algorithm indicated in the
				 * signPolicyHashAlg from the resulting document is equal to the
				 * digest algorithm indicated in the attribute.
				 */

				/**
				 * The use of a zero-sigPolicyHash value is to ensure backwards
				 * compatibility with earlier versions of the current document.
				 * If sigPolicyHash is zero, then the hash value should not be
				 * checked against the calculated hash value of the signature
				 * policy.
				 */
				if (!signPolicyHashAlgFromPolicy.equals(signPolicyHashAlgFromSignature)) {
					xmlPolicy.setProcessingError("The digest algorithm indicated in the SignPolicyHashAlg from the resulting document ("
							+ signPolicyHashAlgFromPolicy + ") is not equal to the digest " + "algorithm (" + signPolicyHashAlgFromSignature + ").");
					xmlPolicy.setDigestAlgorithmsEqual(false);
					xmlPolicy.setStatus(false);
					return;
				} else {
					xmlPolicy.setDigestAlgorithmsEqual(true);
				}

				byte[] recalculatedDigestValue = DSSASN1Utils.getAsn1SignaturePolicyDigest(signPolicyHashAlgFromPolicy, policyBytes);

				boolean equal = Arrays.equals(digestValue, recalculatedDigestValue);
				xmlPolicy.setStatus(equal);
				if (!equal) {
					xmlPolicy.setProcessingError("The policy digest value (" + DatatypeConverter.printBase64Binary(digestValue)
							+ ") does not match the re-calculated digest value (" + DatatypeConverter.printBase64Binary(recalculatedDigestValue) + ").");
					return;
				}

				final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
				final byte[] policyDigestValueFromPolicy = signPolicyHash.getOctets();
				equal = Arrays.equals(digestValue, policyDigestValueFromPolicy);
				xmlPolicy.setStatus(equal);
				if (!equal) {
					xmlPolicy.setProcessingError("The policy digest value (" + DatatypeConverter.printBase64Binary(digestValue)
							+ ") does not match the digest value from the policy file (" + DatatypeConverter.printBase64Binary(policyDigestValueFromPolicy)
							+ ").");
				}
			} else {
				/**
				 * c) In all other cases, compute the digest using the digesting
				 * algorithm indicated in the children of the
				 * property/attribute.
				 */
				byte[] recalculatedDigestValue = DSSUtils.digest(signPolicyHashAlgFromSignature, policyBytes);
				boolean equal = Arrays.equals(digestValue, recalculatedDigestValue);
				xmlPolicy.setStatus(equal);
				if (!equal) {
					xmlPolicy.setProcessingError("The policy digest value (" + DatatypeConverter.printBase64Binary(digestValue)
							+ ") does not match the re-calculated digest value (" + DatatypeConverter.printBase64Binary(recalculatedDigestValue) + ").");
				}
			}

		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.getMessage());
			// Do nothing
			LOG.warn(e.getMessage(), e);
		}
	}

	/**
	 * This method deals with the basic signature data. The retrieved
	 * information is transformed to the JAXB object. The signing certificate
	 * token is returned if found.
	 *
	 * @param signature
	 *            Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature
	 *            The JAXB object containing all diagnostic data pertaining to
	 *            the signature
	 * @return
	 */
	private CertificateToken dealSignature(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final AdvancedSignature masterSignature = signature.getMasterSignature();
		if (masterSignature != null) {

			xmlSignature.setType(AttributeValue.COUNTERSIGNATURE);
			xmlSignature.setParentId(masterSignature.getId());
		}
		performStructuralValidation(signature, xmlSignature);
		performSignatureCryptographicValidation(signature, xmlSignature);
		xmlSignature.setId(signature.getId());
		xmlSignature.setDateTime(signature.getSigningTime());
		final SignatureLevel dataFoundUpToLevel = signature.getDataFoundUpToLevel();
		final String value = dataFoundUpToLevel == null ? "UNKNOWN" : dataFoundUpToLevel.name();
		xmlSignature.setSignatureFormat(value);

		dealWithSignatureProductionPlace(signature, xmlSignature);

		dealWithCommitmentTypeIndication(signature, xmlSignature);

		dealWithClaimedRole(signature, xmlSignature);

		final String contentType = signature.getContentType();
		xmlSignature.setContentType(contentType);

		final String contentIdentifier = signature.getContentIdentifier();
		xmlSignature.setContentIdentifier(contentIdentifier);

		final String contentHints = signature.getContentHints();
		xmlSignature.setContentHints(contentHints);

		dealWithCertifiedRole(signature, xmlSignature);

		final CertificateValidity certificateValidity = dealSigningCertificate(signature, xmlSignature);

		final XmlBasicSignature xmlBasicSignature = getXmlBasicSignature(xmlSignature);
		final EncryptionAlgorithm encryptionAlgorithm = signature.getEncryptionAlgorithm();
		final String encryptionAlgorithmString = encryptionAlgorithm == null ? "?" : encryptionAlgorithm.getName();
		xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmString);
		// signingCertificateValidity can be null in case of a non AdES
		// signature.
		final CertificateToken signingCertificateToken = certificateValidity == null ? null : certificateValidity.getCertificateToken();
		final int keyLength = signingCertificateToken == null ? 0 : DSSPKUtils.getPublicKeySize(signingCertificateToken.getPublicKey());
		xmlBasicSignature.setKeyLengthUsedToSignThisToken(String.valueOf(keyLength));
		final DigestAlgorithm digestAlgorithm = getDigestAlgorithm(signature);
		final String digestAlgorithmString = digestAlgorithm == null ? "?" : digestAlgorithm.getName();
		xmlBasicSignature.setDigestAlgoUsedToSignThisToken(digestAlgorithmString);
		xmlSignature.setBasicSignature(xmlBasicSignature);
		dealSignatureScope(xmlSignature, signature);

		return signingCertificateToken;
	}

	private DigestAlgorithm getDigestAlgorithm(final AdvancedSignature signature) {
		DigestAlgorithm digestAlgorithm = null;
		try {
			digestAlgorithm = signature.getDigestAlgorithm();
		} catch (Exception e) {
			LOG.error("Unable to retrieve digest algorithm : " + e.getMessage());
		}
		return digestAlgorithm;
	}

	private void performStructuralValidation(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final ValidationPolicy validationPolicy = processExecutor.getValidationPolicy();
		if ((validationPolicy == null) || (validationPolicy.getStructuralValidationConstraint(Context.SIGNATURE) == null)) {
			return;
		}
		final String structureValid = signature.validateStructure();
		if (structureValid != null) {
			final XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
			xmlStructuralValidation.setValid(Utils.isStringEmpty(structureValid));
			if (Utils.isStringNotEmpty(structureValid)) {
				xmlStructuralValidation.setMessage(structureValid);
			}
			xmlSignature.setStructuralValidation(xmlStructuralValidation);
		}
	}

	private void dealWithSignatureProductionPlace(AdvancedSignature signature, XmlSignature xmlSignature) {
		final SignatureProductionPlace signatureProductionPlace = signature.getSignatureProductionPlace();
		if (signatureProductionPlace != null) {

			final XmlSignatureProductionPlace xmlSignatureProductionPlace = new XmlSignatureProductionPlace();
			xmlSignatureProductionPlace.setCountryName(signatureProductionPlace.getCountryName());
			xmlSignatureProductionPlace.setStateOrProvince(signatureProductionPlace.getStateOrProvince());
			xmlSignatureProductionPlace.setPostalCode(signatureProductionPlace.getPostalCode());
			xmlSignatureProductionPlace.setAddress(signatureProductionPlace.getStreetAddress());
			xmlSignatureProductionPlace.setCity(signatureProductionPlace.getCity());
			xmlSignature.setSignatureProductionPlace(xmlSignatureProductionPlace);
		}
	}

	private void dealWithCertifiedRole(AdvancedSignature signature, XmlSignature xmlSignature) {
		List<CertifiedRole> certifiedRoles = null;
		try {
			certifiedRoles = signature.getCertifiedSignerRoles();
		} catch (DSSException e) {

			LOG.warn("Exception", e);
			addErrorMessage(xmlSignature, e);
		}
		if (Utils.isCollectionNotEmpty(certifiedRoles)) {
			for (final CertifiedRole certifiedRole : certifiedRoles) {
				final XmlCertifiedRole xmlCertifiedRole = new XmlCertifiedRole();
				xmlCertifiedRole.setCertifiedRole(certifiedRole.getRole());
				xmlCertifiedRole.setNotBefore(certifiedRole.getNotBefore());
				xmlCertifiedRole.setNotAfter(certifiedRole.getNotAfter());
				xmlSignature.getCertifiedRoles().add(xmlCertifiedRole);
			}
		}
	}

	private void dealWithClaimedRole(AdvancedSignature signature, XmlSignature xmlSignature) {
		String[] claimedRoles = null;
		try {
			claimedRoles = signature.getClaimedSignerRoles();
		} catch (DSSException e) {

			LOG.warn("Exception: ", e);
			addErrorMessage(xmlSignature, e);
		}
		if ((claimedRoles != null) && (claimedRoles.length > 0)) {
			List<String> claimedRolesList = new ArrayList<String>();
			for (final String claimedRole : claimedRoles) {
				claimedRolesList.add(claimedRole);
			}
			xmlSignature.setClaimedRoles(claimedRolesList);
		}
	}

	private void dealWithCommitmentTypeIndication(AdvancedSignature signature, XmlSignature xmlSignature) {
		CommitmentType commitmentTypeIndication = null;
		try {
			commitmentTypeIndication = signature.getCommitmentTypeIndication();
		} catch (Exception e) {

			LOG.warn("Exception: ", e);
			addErrorMessage(xmlSignature, e);
		}
		if (commitmentTypeIndication != null) {
			final List<String> identifiers = commitmentTypeIndication.getIdentifiers();
			xmlSignature.setCommitmentTypeIndication(identifiers);
		}
	}

	protected void dealSignatureScope(XmlSignature xmlSignature, AdvancedSignature signature) {
		final List<SignatureScope> signatureScope = signatureScopeFinder.findSignatureScope(signature);
		for (final SignatureScope scope : signatureScope) {
			final XmlSignatureScope xmlSignatureScope = new XmlSignatureScope();
			xmlSignatureScope.setName(scope.getName());
			xmlSignatureScope.setScope(scope.getType());
			xmlSignatureScope.setValue(scope.getDescription());
			xmlSignature.getSignatureScopes().add(xmlSignatureScope);
		}
	}

	private XmlBasicSignature getXmlBasicSignature(XmlSignature xmlSignature) {
		XmlBasicSignature xmlBasicSignature = xmlSignature.getBasicSignature();
		if (xmlBasicSignature == null) {
			xmlBasicSignature = new XmlBasicSignature();
		}
		return xmlBasicSignature;
	}

	/**
	 * This method verifies the cryptographic integrity of the signature: the
	 * references are identified, their digest is checked and then the signature
	 * itself. The result of these verifications is transformed to the JAXB
	 * representation.
	 *
	 * @param signature
	 *            Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature
	 *            The JAXB object containing all diagnostic data pertaining to
	 *            the signature
	 */
	private void performSignatureCryptographicValidation(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final SignatureCryptographicVerification scv = signature.checkSignatureIntegrity();
		final XmlBasicSignature xmlBasicSignature = getXmlBasicSignature(xmlSignature);
		xmlBasicSignature.setReferenceDataFound(scv.isReferenceDataFound());
		xmlBasicSignature.setReferenceDataIntact(scv.isReferenceDataIntact());
		xmlBasicSignature.setSignatureIntact(scv.isSignatureIntact());
		xmlBasicSignature.setSignatureValid(scv.isSignatureValid());
		xmlSignature.setBasicSignature(xmlBasicSignature);
		if (!scv.getErrorMessage().isEmpty()) {

			xmlSignature.setErrorMessage(scv.getErrorMessage());
		}
	}

	/**
	 * This method finds the signing certificate and creates its JAXB object
	 * representation. This is the signing certificate used to produce the main
	 * signature (signature being analysed). If the signingToken is null (the
	 * signing certificate was not found) then Id is set to 0.
	 *
	 * @param signature
	 *            Signature to be validated (can be XAdES, CAdES, PAdES).
	 * @param xmlSignature
	 *            The JAXB object containing all diagnostic data pertaining to
	 *            the signature
	 * @return
	 */
	private CertificateValidity dealSigningCertificate(final AdvancedSignature signature, final XmlSignature xmlSignature) {

		final XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
		signature.checkSigningCertificate();
		final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {

			final CertificateToken signingCertificateToken = theCertificateValidity.getCertificateToken();
			if (signingCertificateToken != null) {

				xmlSignCertType.setId(signingCertificateToken.getDSSId().asXmlId());
			}
			xmlSignCertType.setAttributePresent(theCertificateValidity.isAttributePresent());
			xmlSignCertType.setDigestValuePresent(theCertificateValidity.isDigestPresent());
			xmlSignCertType.setDigestValueMatch(theCertificateValidity.isDigestEqual());
			final boolean issuerSerialMatch = theCertificateValidity.isSerialNumberEqual() && theCertificateValidity.isDistinguishedNameEqual();
			xmlSignCertType.setIssuerSerialMatch(issuerSerialMatch);
			xmlSignCertType.setSigned(theCertificateValidity.getSigned());
			xmlSignature.setSigningCertificate(xmlSignCertType);
		}
		return theCertificateValidity;
	}

	/**
	 * This method creates the SigningCertificate element for the current token.
	 *
	 * @param issuerCertificateToken
	 *            the issuer certificate of the current token
	 * @return
	 */
	protected XmlSigningCertificate xmlForSigningCertificate(final CertificateToken issuerCertificateToken) {
		if (issuerCertificateToken != null) {
			final XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
			xmlSignCertType.setId(issuerCertificateToken.getDSSId().asXmlId());
			return xmlSignCertType;
		}
		return null;
	}

	/**
	 * This method allows to define the sequence of the validator related to a
	 * document to validate. It's only used with ASiC-E container.
	 *
	 * @param validator
	 *            {@code SignedDocumentValidator} corresponding to the next
	 *            signature with in the contained.
	 */
	public void setNextValidator(final DocumentValidator validator) {
		throw new DSSUnsupportedOperationException("This method is not applicable in this context!");
	}

	@Override
	public DocumentValidator getNextValidator() {
		return null;
	}

	@Override
	public DocumentValidator getSubordinatedValidator() {
		return null;
	}

}