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

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEncapsulationType;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureProductionPlace;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTSAGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidationResult;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidatorLoader;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampTokenComparator;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

/**
 * The common class for DiagnosticData creation from a signed/timestamped document
 *
 */
public class SignedDocumentDiagnosticDataBuilder extends DiagnosticDataBuilder {

	/** The signed document */
	protected DSSDocument signedDocument;

	/** The list of signatures */
	protected List<AdvancedSignature> signatures;

	/** The list of timestamp tokens */
	protected Set<TimestampToken> usedTimestamps;

	/** The signature policy provider */
	protected SignaturePolicyProvider signaturePolicyProvider;

	/** Loads a {@code SignaturePolicyValidator} */
	protected SignaturePolicyValidatorLoader signaturePolicyValidatorLoader;

	/** The list of all certificate sources extracted from a validating document (signature(s), timestamp(s)) */
	protected ListCertificateSource documentCertificateSource = new ListCertificateSource();

	/** The list of all CRL revocation sources extracted from a validating document (signature(s), timestamp(s)) */
	protected ListRevocationSource<CRL> documentCRLSource = new ListRevocationSource<>();

	/** The list of all OCSP revocation sources extracted from a validating document (signature(s), timestamp(s)) */
	protected ListRevocationSource<OCSP> documentOCSPSource = new ListRevocationSource<>();

	/** The cached map of signatures */
	protected Map<String, XmlSignature> xmlSignaturesMap = new HashMap<>();

	/** The cached map of timestamps */
	protected Map<String, XmlTimestamp> xmlTimestampsMap = new HashMap<>();

	/** The cached map of original signed data */
	protected Map<String, XmlSignerData> xmlSignedDataMap = new HashMap<>();

	/**
	 * Default constructor instantiating object with null values and empty maps
	 */
	public SignedDocumentDiagnosticDataBuilder() {
		// empty
	}

	@Override
	public SignedDocumentDiagnosticDataBuilder usedCertificates(Set<CertificateToken> usedCertificates) {
		return (SignedDocumentDiagnosticDataBuilder) super.usedCertificates(usedCertificates);
	}

	@Override
	public SignedDocumentDiagnosticDataBuilder usedRevocations(Set<RevocationToken> usedRevocations) {
		return (SignedDocumentDiagnosticDataBuilder) super.usedRevocations(usedRevocations);
	}

	@Override
	public SignedDocumentDiagnosticDataBuilder allCertificateSources(ListCertificateSource trustedCertSources) {
		return (SignedDocumentDiagnosticDataBuilder) super.allCertificateSources(trustedCertSources);
	}

	@Override
	public SignedDocumentDiagnosticDataBuilder validationDate(Date validationDate) {
		return (SignedDocumentDiagnosticDataBuilder) super.validationDate(validationDate);
	}

	@Override
	public SignedDocumentDiagnosticDataBuilder tokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		return (SignedDocumentDiagnosticDataBuilder) super.tokenExtractionStrategy(tokenExtractionStrategy);
	}

	@Override
	public SignedDocumentDiagnosticDataBuilder defaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (SignedDocumentDiagnosticDataBuilder) super.defaultDigestAlgorithm(digestAlgorithm);
	}

	/**
	 * This method allows to set the document which is analysed
	 * 
	 * @param signedDocument the document which is analysed
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder document(DSSDocument signedDocument) {
		this.signedDocument = signedDocument;
		return this;
	}

	/**
	 * This method allows to set the found signatures
	 * 
	 * @param signatures the found signatures
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder foundSignatures(List<AdvancedSignature> signatures) {
		this.signatures = signatures;
		return this;
	}

	/**
	 * This method allows to set the timestamps
	 * 
	 * @param usedTimestamps a set of validated {@link TimestampToken}s
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder usedTimestamps(Set<TimestampToken> usedTimestamps) {
		this.usedTimestamps = usedTimestamps;
		return this;
	}

	/**
	 * This method allows to set the {@code SignaturePolicyProvider}
	 * 
	 * @param signaturePolicyProvider {@link SignaturePolicyProvider}
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder signaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
		this.signaturePolicyProvider = signaturePolicyProvider;
		return this;
	}

	/**
	 * Sets a document Certificate Source containing all sources extracted from the provided signature(s)/timestamp(s)
	 *
	 * @param documentCertificateSource {@link ListCertificateSource} computed from document sources
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder documentCertificateSource(ListCertificateSource documentCertificateSource) {
		this.documentCertificateSource = documentCertificateSource;
		return this;
	}

	/**
	 * This method allows to set the {@code SignaturePolicyValidatorLoader}
	 *
	 * @param signaturePolicyValidatorLoader {@link SignaturePolicyValidatorLoader}
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder signaturePolicyValidatorLoader(
			SignaturePolicyValidatorLoader signaturePolicyValidatorLoader) {
		this.signaturePolicyValidatorLoader = signaturePolicyValidatorLoader;
		return this;
	}

	/**
	 * Sets a document CRL Source containing all sources extracted from the provided signature(s)/timestamp(s)
	 * 
	 * @param documentCRLSource {@link ListRevocationSource} computed from document sources
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder documentCRLSource(ListRevocationSource<CRL> documentCRLSource) {
		this.documentCRLSource = documentCRLSource;
		return this;
	}

	/**
	 * Sets a document OCSP Source containing all sources extracted from the provided signature(s)/timestamp(s)
	 * 
	 * @param documentCRLSource {@link ListRevocationSource} computed from document sources
	 * @return the builder
	 */
	public SignedDocumentDiagnosticDataBuilder documentOCSPSource(ListRevocationSource<OCSP> documentCRLSource) {
		this.documentOCSPSource = documentCRLSource;
		return this;
	}

	/**
	 * Builds {@code XmlDiagnosticData}
	 * 
	 * @return {@link XmlDiagnosticData}
	 */
	@Override
	public XmlDiagnosticData build() {
		Objects.requireNonNull(signedDocument, "signedDocument shall be provided! Use 'document()' method.");

		XmlDiagnosticData diagnosticData = super.build(); // fill certificates and revocation data
		diagnosticData.setDocumentName(removeSpecialCharsForXml(signedDocument.getName()));

		// collect original signer documents
		Collection<XmlSignerData> xmlSignerData = buildXmlSignerDataList(signatures, usedTimestamps);
		diagnosticData.getOriginalDocuments().addAll(xmlSignerData);

		if (Utils.isCollectionNotEmpty(signatures)) {
			Collection<XmlSignature> xmlSignatures = buildXmlSignatures(signatures);
			diagnosticData.getSignatures().addAll(xmlSignatures);
			attachCounterSignatures(signatures);
		}

		if (Utils.isCollectionNotEmpty(usedTimestamps)) {
			List<XmlTimestamp> builtTimestamps = buildXmlTimestamps(usedTimestamps);
			diagnosticData.getUsedTimestamps().addAll(builtTimestamps);
			linkSignaturesAndTimestamps(signatures);
		}

		// link the rest certificates
		super.linkSigningCertificateAndChains(usedCertificates);

		diagnosticData.setOrphanTokens(buildXmlOrphanTokens());

		// timestamped objects must be linked after building of orphan tokens
		if (Utils.isCollectionNotEmpty(usedTimestamps)) {
			linkTimestampsAndTimestampsObjects(usedTimestamps);
		}

		return diagnosticData;
	}

	@Override
	protected void linkSigningCertificateAndChains(Set<CertificateToken> certificates) {
		// skip (certificate chain is build based on provided tokens)
	}

	/**
	 * Escape special characters which cause problems with jaxb or
	 * documentbuilderfactory and namespace aware mode
	 */
	private String removeSpecialCharsForXml(String text) {
		if (Utils.isStringNotEmpty(text)) {
			return text.replace("&", "");
		}
		return Utils.EMPTY_STRING;
	}

	private Collection<XmlSignerData> buildXmlSignerDataList(Collection<AdvancedSignature> signatures,
															 Collection<TimestampToken> timestamps) {
		List<XmlSignerData> signerDataList = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature signature : signatures) {
				signerDataList.addAll(buildXmlSignerData(signature.getSignatureScopes()));
			}
		}
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampToken timestampToken : timestamps) {
				signerDataList.addAll(buildXmlSignerData(timestampToken.getTimestampScopes()));
			}
		}
		return signerDataList;
	}

	private List<XmlSignerData> buildXmlSignerData(List<SignatureScope> signatureScopes) {
		return buildXmlSignerData(signatureScopes, null);
	}

	private List<XmlSignerData> buildXmlSignerData(List<SignatureScope> signatureScopes, XmlSignerData parentSignerData) {
		List<XmlSignerData> result = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (SignatureScope signatureScope : signatureScopes) {
				if (xmlSignedDataMap.get(signatureScope.getDSSIdAsString()) == null) {
					XmlSignerData xmlSignerData = buildXmlSignerData(signatureScope);
					if (parentSignerData != null) {
						xmlSignerData.setParent(parentSignerData);
					}
					result.add(xmlSignerData);
					if (Utils.isCollectionNotEmpty(signatureScope.getChildren())) {
						result.addAll(buildXmlSignerData(signatureScope.getChildren(), xmlSignerData));
					}
				}
			}
		}
		return result;
	}

	private XmlSignerData buildXmlSignerData(SignatureScope signatureScope) {
		String id = signatureScope.getDSSIdAsString();
		XmlSignerData xmlSignerData = xmlSignedDataMap.get(id);
		if (xmlSignerData == null) {
			xmlSignerData = getXmlSignerData(signatureScope);
			xmlSignedDataMap.put(id, xmlSignerData);
		}
		return xmlSignerData;
	}

	private XmlSignerData getXmlSignerData(SignatureScope signatureScope) {
		XmlSignerData xmlSignedData = new XmlSignerData();
		xmlSignedData.setId(identifierProvider.getIdAsString(signatureScope));
		xmlSignedData.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(signatureScope.getDigest()));
		xmlSignedData.setReferencedName(signatureScope.getName());
		return xmlSignedData;
	}

	private Collection<XmlSignature> buildXmlSignatures(List<AdvancedSignature> signatures) {
		List<XmlSignature> builtSignatures = new ArrayList<>();
		for (AdvancedSignature advancedSignature : signatures) {
			String id = advancedSignature.getId();
			XmlSignature xmlSignature = xmlSignaturesMap.get(id);
			if (xmlSignature == null) {
				xmlSignature = getXmlSignature(advancedSignature);
				builtSignatures.add(xmlSignature);
			}
		}
		return builtSignatures;
	}

	private void attachCounterSignatures(List<AdvancedSignature> signatures) {
		for (AdvancedSignature advancedSignature : signatures) {
			if (advancedSignature.isCounterSignature()) {
				XmlSignature currentSignature = xmlSignaturesMap.get(advancedSignature.getId());
				// attach master
				AdvancedSignature masterSignature = advancedSignature.getMasterSignature();
				XmlSignature xmlMasterSignature = xmlSignaturesMap.get(masterSignature.getId());
				currentSignature.setCounterSignature(true);
				currentSignature.setParent(xmlMasterSignature);
			}
		}
	}

	private XmlSignature getXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = buildDetachedXmlSignature(signature);
		checkDuplicates(xmlSignature, signature);

		setXmlSigningCertificate(xmlSignature, signature);
		setXmlPolicy(xmlSignature, signature);

		xmlSignature.setFoundCertificates(getXmlFoundCertificates(signature.getDSSId(), signature.getCertificateSource()));
		xmlSignature.setFoundRevocations(getXmlFoundRevocations(signature.getCRLSource(), signature.getOCSPSource()));
		xmlSignature.setSignatureScopes(getXmlSignatureScopes(signature.getSignatureScopes()));

		xmlSignaturesMap.put(signature.getId(), xmlSignature);

		return xmlSignature;
	}

	private void checkDuplicates(XmlSignature xmlSignature, AdvancedSignature signature) {
		if (hasDuplicate(signature)) {
			xmlSignature.setDuplicated(true);
		}
	}

	private boolean hasDuplicate(AdvancedSignature currentSignature) {
		for (AdvancedSignature signature : signatures) {
			if (currentSignature != signature
					&& (currentSignature.getId().equals(signature.getId()) ||
					(currentSignature.getDAIdentifier() != null && currentSignature.getDAIdentifier().equals(signature.getDAIdentifier())
							&& currentSignature.getSignatureFilename() != null && currentSignature.getSignatureFilename().equals(signature.getSignatureFilename())))) {
				return true;
			}
		}
		return false;
	}

	private void setXmlSigningCertificate(XmlSignature xmlSignature, AdvancedSignature signature) {
		final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		PublicKey signingCertificatePublicKey = null;
		if (theCertificateValidity != null) {
			xmlSignature.setSigningCertificate(getXmlSigningCertificate(signature.getDSSId(), theCertificateValidity));
			xmlSignature.setCertificateChain(getXmlForCertificateChain(theCertificateValidity, signature.getCertificateSource()));
			signingCertificatePublicKey = theCertificateValidity.getPublicKey();
		}

		xmlSignature.setBasicSignature(getXmlBasicSignature(signature, signingCertificatePublicKey));
		xmlSignature.setDigestMatchers(getXmlDigestMatchers(signature));
	}

	private void setXmlPolicy(XmlSignature xmlSignature, AdvancedSignature signature) {
		if (signature.getSignaturePolicy() != null) {
			XmlPolicyBuilder policyBuilder = getPolicyBuilder(signature);
			xmlSignature.setPolicy(policyBuilder.build());
			xmlSignature.setSignaturePolicyStore(policyBuilder.buildSignaturePolicyStore());
		}
	}

	/**
	 * Builds {@code XmlSignature}
	 * 
	 * @param signature {@link AdvancedSignature}
	 * @return {@link XmlSignature}
	 */
	public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setSignatureFilename(removeSpecialCharsForXml(signature.getSignatureFilename()));

		xmlSignature.setId(identifierProvider.getIdAsString(signature));
		xmlSignature.setDAIdentifier(signature.getDAIdentifier());
		xmlSignature.setClaimedSigningTime(signature.getSigningTime());
		xmlSignature.setStructuralValidation(getXmlStructuralValidation(signature));
		xmlSignature.setSignatureFormat(signature.getDataFoundUpToLevel());

		xmlSignature.setSignatureProductionPlace(
				getXmlSignatureProductionPlace(signature.getSignatureProductionPlace()));
		xmlSignature.getCommitmentTypeIndications().addAll(
				getXmlCommitmentTypeIndications(signature.getCommitmentTypeIndications()));
		xmlSignature.getSignerRole().addAll(getXmlSignerRoles(signature.getSignerRoles()));

		xmlSignature.setContentType(signature.getContentType());
		xmlSignature.setMimeType(signature.getMimeType());

		xmlSignature.setSignatureDigestReference(getXmlSignatureDigestReference(signature));

		xmlSignature.setDataToBeSignedRepresentation(getXmlDataToBeSignedRepresentation(signature));
		xmlSignature.setSignerDocumentRepresentations(getXmlSignerDocumentRepresentations(signature));

		xmlSignature.setSignatureValue(signature.getSignatureValue());

		return xmlSignature;
	}

	private XmlStructuralValidation getXmlStructuralValidation(AdvancedSignature signature) {
		List<String> structureValidationResult = signature.getStructureValidationResult();
		final XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
		xmlStructuralValidation.setValid(Utils.isCollectionEmpty(structureValidationResult));
		if (Utils.isCollectionNotEmpty(structureValidationResult)) {
			xmlStructuralValidation.getMessages().addAll(structureValidationResult);
		}
		return xmlStructuralValidation;
	}

	private XmlSignatureProductionPlace getXmlSignatureProductionPlace(SignatureProductionPlace signatureProductionPlace) {
		if (signatureProductionPlace != null) {
			final XmlSignatureProductionPlace xmlSignatureProductionPlace = new XmlSignatureProductionPlace();
			xmlSignatureProductionPlace.setCountryName(emptyToNull(signatureProductionPlace.getCountryName()));
			xmlSignatureProductionPlace.setStateOrProvince(emptyToNull(signatureProductionPlace.getStateOrProvince()));
			xmlSignatureProductionPlace.setPostOfficeBoxNumber(emptyToNull(signatureProductionPlace.getPostOfficeBoxNumber()));
			xmlSignatureProductionPlace.setPostalCode(emptyToNull(signatureProductionPlace.getPostalCode()));
			xmlSignatureProductionPlace.setStreetAddress(emptyToNull(signatureProductionPlace.getStreetAddress()));
			xmlSignatureProductionPlace.setCity(emptyToNull(signatureProductionPlace.getCity()));
			if (Utils.isCollectionNotEmpty(signatureProductionPlace.getPostalAddress())) {
				xmlSignatureProductionPlace.getPostalAddress().addAll(signatureProductionPlace.getPostalAddress());
			}
			return xmlSignatureProductionPlace;
		}
		return null;
	}

	/**
	 * If text is empty returns NULL, or original text otherwise
	 *
	 * @param text {@link String}
	 * @return {@link String}
	 */
	protected String emptyToNull(String text) {
		if (Utils.isStringEmpty(text)) {
			return null;
		}
		return text;
	}

	private List<XmlCommitmentTypeIndication> getXmlCommitmentTypeIndications(
			List<CommitmentTypeIndication> commitmentTypeIndications) {
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			List<XmlCommitmentTypeIndication> xmlCommitmentTypeIndications = new ArrayList<>();
			for (CommitmentTypeIndication commitmentTypeIndication : commitmentTypeIndications) {
				xmlCommitmentTypeIndications.add(getXmlCommitmentTypeIndication(commitmentTypeIndication));
			}
			return xmlCommitmentTypeIndications;
		}
		return Collections.emptyList();
	}

	private XmlCommitmentTypeIndication getXmlCommitmentTypeIndication(
			CommitmentTypeIndication commitmentTypeIndication) {
		XmlCommitmentTypeIndication xmlCommitmentTypeIndication = new XmlCommitmentTypeIndication();
		xmlCommitmentTypeIndication.setIdentifier(commitmentTypeIndication.getIdentifier());
		xmlCommitmentTypeIndication.setDescription(commitmentTypeIndication.getDescription());
		xmlCommitmentTypeIndication.setDocumentationReferences(commitmentTypeIndication.getDocumentReferences());
		if (commitmentTypeIndication.isAllDataSignedObjects()) {
			xmlCommitmentTypeIndication.setAllDataSignedObjects(commitmentTypeIndication.isAllDataSignedObjects());
		} else {
			xmlCommitmentTypeIndication.setObjectReferences(commitmentTypeIndication.getObjectReferences());
		}
		return xmlCommitmentTypeIndication;
	}

	private List<XmlSignerRole> getXmlSignerRoles(Collection<SignerRole> signerRoles) {
		List<XmlSignerRole> xmlSignerRoles = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(signerRoles)) {
			for (SignerRole signerRole : signerRoles) {
				XmlSignerRole xmlSignerRole = new XmlSignerRole();
				xmlSignerRole.setRole(signerRole.getRole());
				xmlSignerRole.setCategory(signerRole.getCategory());
				xmlSignerRole.setNotBefore(signerRole.getNotBefore());
				xmlSignerRole.setNotAfter(signerRole.getNotAfter());
				xmlSignerRoles.add(xmlSignerRole);
			}
		}
		return xmlSignerRoles;
	}

	private XmlBasicSignature getXmlBasicSignature(AdvancedSignature signature, PublicKey signingCertificatePublicKey) {
		XmlBasicSignature xmlBasicSignature = new XmlBasicSignature();
		xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(signature.getEncryptionAlgorithm());
		xmlBasicSignature.setKeyLengthUsedToSignThisToken(DSSPKUtils.getStringPublicKeySize(signingCertificatePublicKey));
		xmlBasicSignature.setDigestAlgoUsedToSignThisToken(signature.getDigestAlgorithm());
		xmlBasicSignature.setMaskGenerationFunctionUsedToSignThisToken(signature.getMaskGenerationFunction());

		SignatureCryptographicVerification scv = signature.getSignatureCryptographicVerification();
		xmlBasicSignature.setSignatureIntact(scv.isSignatureIntact());
		xmlBasicSignature.setSignatureValid(scv.isSignatureValid());
		return xmlBasicSignature;
	}

	private List<XmlDigestMatcher> getXmlDigestMatchers(AdvancedSignature signature) {
		List<XmlDigestMatcher> refs = new ArrayList<>();
		List<ReferenceValidation> refValidations = signature.getReferenceValidations();
		if (Utils.isCollectionNotEmpty(refValidations)) {
			for (ReferenceValidation referenceValidation : refValidations) {
				refs.add(getXmlDigestMatcher(referenceValidation));
				List<ReferenceValidation> dependentValidations = referenceValidation.getDependentValidations();
				if (Utils.isCollectionNotEmpty(dependentValidations)
						&& (Utils.isCollectionNotEmpty(signature.getDetachedContents())
								|| isAtLeastOneFound(dependentValidations))) {
					for (ReferenceValidation dependentValidation : referenceValidation.getDependentValidations()) {
						refs.add(getXmlDigestMatcher(dependentValidation));
					}
				}
			}
		}
		return refs;
	}

	private XmlDigestMatcher getXmlDigestMatcher(ReferenceValidation referenceValidation) {
		XmlDigestMatcher ref = new XmlDigestMatcher();
		ref.setType(referenceValidation.getType());
		ref.setName(referenceValidation.getName());
		Digest digest = referenceValidation.getDigest();
		if (digest != null) {
			ref.setDigestValue(digest.getValue());
			ref.setDigestMethod(digest.getAlgorithm());
		}
		ref.setDataFound(referenceValidation.isFound());
		ref.setDataIntact(referenceValidation.isIntact());
		if (referenceValidation.isDuplicated()) {
			ref.setDuplicated(referenceValidation.isDuplicated());
		}
		return ref;
	}

	/**
	 * Checks if at least one Manifest entry was found
	 * 
	 * @return TRUE if at least one ManifestEntry was found, FALSE otherwise
	 */
	private boolean isAtLeastOneFound(List<ReferenceValidation> referenceValidations) {
		for (ReferenceValidation referenceValidation : referenceValidations) {
			if (referenceValidation.isFound()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method deals with the signature policy. The retrieved object is a
	 * builder for an {@code XmlPolicy} and {@code XmlSignaturePolicyStore}
	 *
	 * @param signature {@link AdvancedSignature}
	 * 
	 */
	private XmlPolicyBuilder getPolicyBuilder(AdvancedSignature signature) {
		Objects.requireNonNull(signaturePolicyValidatorLoader, "SignaturePolicyValidatorLoader shall be defined!");
		SignaturePolicy signaturePolicy = signature.getSignaturePolicy();
		SignaturePolicyStore signaturePolicyStore = signature.getSignaturePolicyStore();

		DSSDocument policyContent = extractSignaturePolicyContent(signaturePolicy, signaturePolicyStore);
		signaturePolicy.setPolicyContent(policyContent);

		SignaturePolicyValidator signaturePolicyValidator = signaturePolicyValidatorLoader.loadValidator(signaturePolicy);
		SignaturePolicyValidationResult validationResult = signaturePolicyValidator.validate(signaturePolicy);

		XmlPolicyBuilder xmlPolicyBuilder = new XmlPolicyBuilder(signaturePolicy, validationResult);
		xmlPolicyBuilder.setSignaturePolicyStore(signaturePolicyStore);
		return xmlPolicyBuilder;
	}

	private DSSDocument extractSignaturePolicyContent(SignaturePolicy signaturePolicy, SignaturePolicyStore signaturePolicyStore) {
		if (signaturePolicyStore != null) {
			if (signaturePolicyStore.getSignaturePolicyContent() != null) {
				return signaturePolicyStore.getSignaturePolicyContent();
			} else if (signaturePolicyStore.getSigPolDocLocalURI() != null && signaturePolicyProvider != null) {
				return signaturePolicyProvider.getSignaturePolicyByUrl(signaturePolicyStore.getSigPolDocLocalURI());
			}
		}
		if (signaturePolicyProvider != null) {
			return signaturePolicyProvider.getSignaturePolicy(signaturePolicy.getIdentifier(), signaturePolicy.getUri());
		}
		return null;
	}

	private XmlSignatureDigestReference getXmlSignatureDigestReference(AdvancedSignature signature) {
		SignatureDigestReference signatureDigestReference = signature
				.getSignatureDigestReference(defaultDigestAlgorithm);
		if (signatureDigestReference != null) {
			XmlSignatureDigestReference xmlDigestReference = new XmlSignatureDigestReference();
			xmlDigestReference.setCanonicalizationMethod(signatureDigestReference.getCanonicalizationMethod());
			xmlDigestReference.setDigestMethod(signatureDigestReference.getDigestAlgorithm());
			xmlDigestReference.setDigestValue(signatureDigestReference.getDigestValue());
			return xmlDigestReference;
		}
		return null;
	}

	private XmlDigestAlgoAndValue getXmlDataToBeSignedRepresentation(AdvancedSignature signature) {
		Digest dtbsr = signature.getDataToBeSignedRepresentation();
		if (dtbsr != null) {
			return getXmlDigestAlgoAndValue(dtbsr);
		}
		return null;
	}

	private XmlSignerDocumentRepresentations getXmlSignerDocumentRepresentations(AdvancedSignature signature) {
		if (signature.getDetachedContents() == null) {
			return null;
		}
		XmlSignerDocumentRepresentations signerDocumentRepresentation = new XmlSignerDocumentRepresentations();
		signerDocumentRepresentation.setDocHashOnly(signature.isDocHashOnlyValidation());
		signerDocumentRepresentation.setHashOnly(signature.isHashOnlyValidation());
		return signerDocumentRepresentation;
	}

	private XmlFoundRevocations getXmlFoundRevocations(OfflineRevocationSource<CRL> crlSource,
			OfflineRevocationSource<OCSP> ocspSource) {
		XmlFoundRevocations foundRevocations = new XmlFoundRevocations();
		foundRevocations.getRelatedRevocations().addAll(getXmlRelatedRevocations(crlSource, ocspSource));
		foundRevocations.getOrphanRevocations().addAll(getXmlOrphanRevocations(crlSource, ocspSource));
		foundRevocations.getOrphanRevocations().addAll(getXmlOrphanRevocationRefs(crlSource, ocspSource));
		return foundRevocations;
	}

	private List<XmlRelatedRevocation> getXmlRelatedRevocations(OfflineRevocationSource<CRL> crlSource,
			OfflineRevocationSource<OCSP> ocspSource) {
		List<XmlRelatedRevocation> xmlRelatedRevocations = new ArrayList<>();
		addRelatedRevocations(xmlRelatedRevocations, crlSource);
		addRelatedRevocations(xmlRelatedRevocations, ocspSource);
		return xmlRelatedRevocations;
	}

	private <R extends Revocation> void addRelatedRevocations(List<XmlRelatedRevocation> result,
			OfflineRevocationSource<R> source) {
		for (Entry<RevocationToken<R>, Set<RevocationOrigin>> entry : source.getUniqueRevocationTokensWithOrigins().entrySet()) {
			RevocationToken<R> token = entry.getKey();
			String id = token.getDSSIdAsString();
			XmlRevocation xmlRevocation = xmlRevocationsMap.get(id);
			if (xmlRevocation != null) {
				XmlRelatedRevocation xmlRelatedRevocation = new XmlRelatedRevocation();
				xmlRelatedRevocation.setRevocation(xmlRevocation);
				xmlRelatedRevocation.setType(token.getRevocationType());
				xmlRelatedRevocation.getOrigins().addAll(entry.getValue());
				xmlRelatedRevocation.getRevocationRefs().addAll(getXmlRevocationRefs(xmlRevocation.getId(),
						source.findRefsAndOriginsForRevocationToken(token)));
				result.add(xmlRelatedRevocation);
			}
		}
	}

	private List<XmlOrphanRevocation> getXmlOrphanRevocations(OfflineRevocationSource<CRL> crlSource,
			OfflineRevocationSource<OCSP> ocspSource) {
		List<XmlOrphanRevocation> xmlOrphanRevocations = new ArrayList<>();
		addOrphanRevocations(xmlOrphanRevocations, crlSource);
		addOrphanRevocations(xmlOrphanRevocations, ocspSource);
		return xmlOrphanRevocations;
	}

	private <R extends Revocation> void addOrphanRevocations(List<XmlOrphanRevocation> xmlOrphanRevocations,
			OfflineRevocationSource<R> source) {
		Map<EncapsulatedRevocationTokenIdentifier<R>, Set<RevocationOrigin>> allBinariesWithOrigins =
				source.getAllRevocationBinariesWithOrigins();
		for (Entry<EncapsulatedRevocationTokenIdentifier<R>, Set<RevocationOrigin>> entry : allBinariesWithOrigins.entrySet()) {
			EncapsulatedRevocationTokenIdentifier<R> token = entry.getKey();
			String tokenId = token.asXmlId();
			if (!xmlRevocationsMap.containsKey(tokenId)) {
				XmlOrphanRevocation xmlOrphanRevocation = getXmlOrphanRevocation(token, entry.getValue());
				xmlOrphanRevocation.getRevocationRefs().addAll(getXmlRevocationRefs(tokenId, source.findRefsAndOriginsForBinary(token)));
				xmlOrphanRevocations.add(xmlOrphanRevocation);
			}
		}
	}

	private List<XmlOrphanRevocation> getXmlOrphanRevocationRefs(OfflineRevocationSource<CRL> crlSource,
			OfflineRevocationSource<OCSP> ocspSource) {
		List<XmlOrphanRevocation> xmlOrphanRevocationRefs = new ArrayList<>();
		addOrphanRevocationRefs(xmlOrphanRevocationRefs, crlSource, documentCRLSource);
		addOrphanRevocationRefs(xmlOrphanRevocationRefs, ocspSource, documentOCSPSource);
		return xmlOrphanRevocationRefs;
	}

	private <R extends Revocation> void addOrphanRevocationRefs(List<XmlOrphanRevocation> xmlOrphanRevocationRefs,
			OfflineRevocationSource<R> source, ListRevocationSource<R> allSources) {
		Map<RevocationRef<R>, Set<RevocationRefOrigin>> orphanRevocationReferencesWithOrigins =
				source.getOrphanRevocationReferencesWithOrigins();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : orphanRevocationReferencesWithOrigins.entrySet()) {
			RevocationRef<R> ref = entry.getKey();
			if (allSources.isOrphan(ref) && sourceDoesNotContainOrphanBinaries(source, ref)) {
				xmlOrphanRevocationRefs.add(createOrphanRevocationFromRef(ref, entry.getValue()));
			}
		}
	}

	private <R extends Revocation> boolean sourceDoesNotContainOrphanBinaries(OfflineRevocationSource<R> source,
			RevocationRef<R> ref) {
		String tokenId = referenceMap.get(ref.getDSSIdAsString());
		if (tokenId == null) {
			return true;
		}
		for (Identifier revocationIdentifier : source.getAllRevocationBinaries()) {
			if (tokenId.equals(revocationIdentifier.asXmlId())) {
				return false;
			}
		}
		return true;
	}

	private <R extends Revocation> XmlOrphanRevocation getXmlOrphanRevocation(
			EncapsulatedRevocationTokenIdentifier<R> token, Set<RevocationOrigin> origins) {
		XmlOrphanRevocation xmlOrphanRevocation = new XmlOrphanRevocation();
		if (token instanceof CRLBinary) {
			xmlOrphanRevocation.setType(RevocationType.CRL);
		} else {
			xmlOrphanRevocation.setType(RevocationType.OCSP);
		}
		xmlOrphanRevocation.getOrigins().addAll(origins);
		xmlOrphanRevocation.setToken(createOrphanTokenFromRevocationIdentifier(token));
		return xmlOrphanRevocation;
	}

	/**
	 * Creates an orphan revocation token from {@code EncapsulatedRevocationTokenIdentifier}
	 *
	 * @param revocationIdentifier {@link EncapsulatedRevocationTokenIdentifier}
	 * @param <R> {@link Revocation}
	 * @return {@link XmlOrphanRevocationToken}
	 */
	protected <R extends Revocation> XmlOrphanRevocationToken createOrphanTokenFromRevocationIdentifier(
			EncapsulatedRevocationTokenIdentifier<R> revocationIdentifier) {
		XmlOrphanRevocationToken orphanToken = new XmlOrphanRevocationToken();
		orphanToken.setEncapsulationType(XmlEncapsulationType.BINARIES);
		orphanToken.setId(identifierProvider.getIdAsString(revocationIdentifier));
		if (tokenExtractionStrategy.isRevocationData()) {
			orphanToken.setBase64Encoded(revocationIdentifier.getBinaries());
		} else {
			byte[] digestValue = revocationIdentifier.getDigestValue(defaultDigestAlgorithm);
			orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, digestValue));
		}
		if (revocationIdentifier instanceof CRLBinary) {
			orphanToken.setRevocationType(RevocationType.CRL);
		} else if (revocationIdentifier instanceof OCSPResponseBinary) {
			orphanToken.setRevocationType(RevocationType.OCSP);
			OCSPResponseBinary ocspResponseBinary = (OCSPResponseBinary) revocationIdentifier;
			OCSPCertificateSource ocspCertificateSource = new OCSPCertificateSource(ocspResponseBinary.getBasicOCSPResp());
			getXmlFoundCertificates(ocspResponseBinary, ocspCertificateSource); // create from OCSP Certificate Source
		}
		xmlOrphanRevocationTokensMap.put(revocationIdentifier.asXmlId(), orphanToken);
		return orphanToken;
	}

	private <R extends Revocation> XmlOrphanRevocation createOrphanRevocationFromRef(RevocationRef<R> ref,
			Set<RevocationRefOrigin> origins) {
		XmlOrphanRevocation xmlOrphanRevocation = new XmlOrphanRevocation();

		XmlOrphanRevocationToken orphanToken = new XmlOrphanRevocationToken();
		orphanToken.setEncapsulationType(XmlEncapsulationType.REFERENCE);
		orphanToken.setId(identifierProvider.getIdAsString(ref));
		if (ref.getDigest() != null) {
			orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(ref.getDigest()));
		}
		xmlOrphanRevocationTokensMap.put(ref.getDSSIdAsString(), orphanToken);

		xmlOrphanRevocation.setToken(orphanToken);
		if (ref instanceof CRLRef) {
			orphanToken.setRevocationType(RevocationType.CRL);
			xmlOrphanRevocation.setType(RevocationType.CRL);
			xmlOrphanRevocation.getRevocationRefs().add(getXmlCRLRevocationRef((CRLRef) ref, origins));
		} else {
			orphanToken.setRevocationType(RevocationType.OCSP);
			xmlOrphanRevocation.setType(RevocationType.OCSP);
			xmlOrphanRevocation.getRevocationRefs().add(getXmlOCSPRevocationRef((OCSPRef) ref, origins));
		}
		return xmlOrphanRevocation;
	}

	private List<XmlSignatureScope> getXmlSignatureScopes(List<SignatureScope> scopes) {
		List<XmlSignatureScope> xmlScopes = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(scopes)) {
			for (SignatureScope signatureScope : scopes) {
				xmlScopes.add(getXmlSignatureScope(signatureScope));
				if (Utils.isCollectionNotEmpty(signatureScope.getChildren())) {
					xmlScopes.addAll(getXmlSignatureScopes(signatureScope.getChildren()));
				}
			}
		}
		return xmlScopes;
	}

	private XmlSignatureScope getXmlSignatureScope(SignatureScope scope) {
		final XmlSignatureScope xmlSignatureScope = new XmlSignatureScope();
		xmlSignatureScope.setName(scope.getName());
		xmlSignatureScope.setScope(scope.getType());
		xmlSignatureScope.setDescription(scope.getDescription());
		xmlSignatureScope.setTransformations(scope.getTransformations());
		xmlSignatureScope.setSignerData(xmlSignedDataMap.get(scope.getDSSIdAsString()));
		return xmlSignatureScope;
	}

	private List<XmlTimestamp> buildXmlTimestamps(Set<TimestampToken> timestamps) {
		List<XmlTimestamp> xmlTimestampsList = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			List<TimestampToken> tokens = new ArrayList<>(timestamps);
			tokens.sort(new TimestampTokenComparator());
			for (TimestampToken timestampToken : tokens) {
				String id = timestampToken.getDSSIdAsString();
				XmlTimestamp xmlTimestamp = buildDetachedXmlTimestamp(timestampToken);
				xmlTimestampsMap.put(id, xmlTimestamp);
				xmlTimestampsList.add(xmlTimestamp);
			}
		}
		return xmlTimestampsList;
	}

	/**
	 * This method builds {@code XmlTimestamp} from {@code TimestampToken}
	 *
	 * @param timestampToken {@link TimestampToken}
	 * @return {@link XmlTimestamp}
	 */
	protected XmlTimestamp buildDetachedXmlTimestamp(final TimestampToken timestampToken) {

		final XmlTimestamp xmlTimestampToken = new XmlTimestamp();

		xmlTimestampToken.setId(identifierProvider.getIdAsString(timestampToken));
		xmlTimestampToken.setType(timestampToken.getTimeStampType());
		// property is defined only for archival timestamps
		xmlTimestampToken.setArchiveTimestampType(timestampToken.getArchiveTimestampType());

		xmlTimestampToken.setProductionTime(timestampToken.getGenerationTime());
		xmlTimestampToken.setTimestampFilename(timestampToken.getFileName());
		xmlTimestampToken.getDigestMatchers().addAll(getXmlDigestMatchers(timestampToken));
		xmlTimestampToken.setBasicSignature(getXmlBasicSignature(timestampToken));
		xmlTimestampToken.setSignerInformationStore(
				getXmlSignerInformationStore(timestampToken.getSignerInformationStoreInfos()));
		xmlTimestampToken.setTSAGeneralName(getXmlTSAGeneralName(timestampToken));

		final CandidatesForSigningCertificate candidatesForSigningCertificate = timestampToken.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {
			xmlTimestampToken.setSigningCertificate(getXmlSigningCertificate(timestampToken.getDSSId(), theCertificateValidity));
			xmlTimestampToken.setCertificateChain(getXmlForCertificateChain(theCertificateValidity, timestampToken.getCertificateSource()));
		}

		xmlTimestampToken.setFoundCertificates(
				getXmlFoundCertificates(timestampToken.getDSSId(), timestampToken.getCertificateSource()));
		xmlTimestampToken.setFoundRevocations(
				getXmlFoundRevocations(timestampToken.getCRLSource(), timestampToken.getOCSPSource()));

		if (Utils.isCollectionNotEmpty(timestampToken.getTimestampScopes())) {
			xmlTimestampToken.setTimestampScopes(getXmlSignatureScopes(timestampToken.getTimestampScopes()));
		}

		if (tokenExtractionStrategy.isTimestamp()) {
			xmlTimestampToken.setBase64Encoded(timestampToken.getEncoded());
		} else {
			byte[] certDigest = timestampToken.getDigest(defaultDigestAlgorithm);
			xmlTimestampToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, certDigest));
		}

		return xmlTimestampToken;
	}

	private List<XmlDigestMatcher> getXmlDigestMatchers(TimestampToken timestampToken) {
		List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
		digestMatchers.add(getImprintDigestMatcher(timestampToken));
		digestMatchers.addAll(getManifestEntriesDigestMatchers(timestampToken.getManifestFile()));
		return digestMatchers;
	}

	private XmlDigestMatcher getImprintDigestMatcher(TimestampToken timestampToken) {
		XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
		digestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
		Digest messageImprint = timestampToken.getMessageImprint();
		if (messageImprint != null) {
			digestMatcher.setDigestMethod(messageImprint.getAlgorithm());
			digestMatcher.setDigestValue(messageImprint.getValue());
		}
		digestMatcher.setDataFound(timestampToken.isMessageImprintDataFound());
		digestMatcher.setDataIntact(timestampToken.isMessageImprintDataIntact());
		ManifestFile manifestFile = timestampToken.getManifestFile();
		if (manifestFile != null) {
			digestMatcher.setName(manifestFile.getFilename());
		}
		return digestMatcher;
	}

	private List<XmlDigestMatcher> getManifestEntriesDigestMatchers(ManifestFile manifestFile) {
		List<XmlDigestMatcher> digestMatchers = new ArrayList<>();
		if (manifestFile != null && Utils.isCollectionNotEmpty(manifestFile.getEntries())) {
			for (ManifestEntry entry : manifestFile.getEntries()) {
				XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
				digestMatcher.setType(DigestMatcherType.MANIFEST_ENTRY);
				Digest digest = entry.getDigest();
				if (digest != null) {
					digestMatcher.setDigestMethod(digest.getAlgorithm());
					digestMatcher.setDigestValue(digest.getValue());
				}
				digestMatcher.setDataFound(entry.isFound());
				digestMatcher.setDataIntact(entry.isIntact());
				digestMatcher.setName(entry.getFileName());

				digestMatchers.add(digestMatcher);
			}
		}
		return digestMatchers;
	}

	/**
	 * Builds a list of {@code XmlSignerInfo} from {@code SignerIdentifier}s
	 *
	 * @param signerIdentifiers a set of {@link SignerIdentifier}
	 * @return a list of {@link XmlSignerInfo}s
	 */
	protected List<XmlSignerInfo> getXmlSignerInformationStore(Set<SignerIdentifier> signerIdentifiers) {
		if (Utils.isCollectionNotEmpty(signerIdentifiers)) {
			List<XmlSignerInfo> signerInfos = new ArrayList<>();
			for (SignerIdentifier signerIdentifier : signerIdentifiers) {
				signerInfos.add(getXmlSignerInfo(signerIdentifier));
			}
			return signerInfos;
		}
		return null;
	}

	private XmlTSAGeneralName getXmlTSAGeneralName(TimestampToken timestampToken) {
		X500Principal tstInfoTsa = timestampToken.getTSTInfoTsa();
		if (tstInfoTsa != null) {
			XmlTSAGeneralName xmlTSAGeneralName = new XmlTSAGeneralName();

			X500PrincipalHelper x500PrincipalHelper = new X500PrincipalHelper(tstInfoTsa);
			xmlTSAGeneralName.setValue(x500PrincipalHelper.getRFC2253());

			X500Principal issuerX500Principal = timestampToken.getIssuerX500Principal();
			if (issuerX500Principal != null) {
				xmlTSAGeneralName.setContentMatch(DSSASN1Utils.x500PrincipalAreEquals(tstInfoTsa, issuerX500Principal));
				xmlTSAGeneralName.setOrderMatch(tstInfoTsa.equals(issuerX500Principal));
			}

			return xmlTSAGeneralName;
		}
		return null;
	}

	private void linkSignaturesAndTimestamps(List<AdvancedSignature> signatures) {
		for (AdvancedSignature advancedSignature : signatures) {
			XmlSignature currentSignature = xmlSignaturesMap.get(advancedSignature.getId());
			// attach timestamps
			currentSignature.setFoundTimestamps(getXmlFoundTimestamps(advancedSignature));
		}
	}

	private List<XmlFoundTimestamp> getXmlFoundTimestamps(AdvancedSignature signature) {
		List<XmlFoundTimestamp> foundTimestamps = new ArrayList<>();
		for (TimestampToken timestampToken : signature.getAllTimestamps()) {
			XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
			foundTimestamp.setTimestamp(xmlTimestampsMap.get(timestampToken.getDSSIdAsString()));
			foundTimestamps.add(foundTimestamp);
		}
		return foundTimestamps;
	}

	private void linkTimestampsAndTimestampsObjects(Set<TimestampToken> timestamps) {
		for (TimestampToken timestampToken : timestamps) {
			XmlTimestamp xmlTimestampToken = xmlTimestampsMap.get(timestampToken.getDSSIdAsString());
			xmlTimestampToken.setTimestampedObjects(getXmlTimestampedObjects(timestampToken));
		}
	}

	private List<XmlTimestampedObject> getXmlTimestampedObjects(TimestampToken timestampToken) {
		List<TimestampedReference> timestampReferences = timestampToken.getTimestampedReferences();
		if (Utils.isCollectionNotEmpty(timestampReferences)) {
			List<XmlTimestampedObject> objects = new ArrayList<>();
			Set<String> addedTokenIds = new HashSet<>();
			for (final TimestampedReference timestampReference : timestampReferences) {
				String id = timestampReference.getObjectId();

				XmlTimestampedObject timestampedObject = createXmlTimestampedObject(timestampReference);
				if (timestampedObject.getToken() == null) {
					throw new DSSException(String.format("Token with Id '%s' not found", id));
				}
				id = timestampedObject.getToken().getId(); // can change in case of ref
				if (addedTokenIds.contains(id)) {
					// skip the ref if it was added before
					continue;
				}
				addedTokenIds.add(id);

				objects.add(timestampedObject);
			}
			return objects;
		}
		return null;
	}

	private XmlTimestampedObject createXmlTimestampedObject(final TimestampedReference timestampReference) {
		XmlTimestampedObject timestampedObj = new XmlTimestampedObject();
		timestampedObj.setCategory(timestampReference.getCategory());

		String objectId = timestampReference.getObjectId();

		switch (timestampReference.getCategory()) {
		case SIGNATURE:
			timestampedObj.setToken(xmlSignaturesMap.get(objectId));
			return timestampedObj;

		case CERTIFICATE:
			if (!isUsedToken(objectId, usedCertificates)) {
				String relatedCertificateId = referenceMap.get(objectId);
				if (relatedCertificateId != null) {
					objectId = relatedCertificateId;
					if (!isUsedToken(objectId, usedCertificates)) {
						break; // break to create an orphan token
					}
				} else {
					break;
				}
			}
			timestampedObj.setToken(xmlCertsMap.get(objectId));
			return timestampedObj;

		case REVOCATION:
			if (!isUsedToken(objectId, usedRevocations)) {
				String relatedRevocationId = referenceMap.get(objectId);
				if (relatedRevocationId != null) {
					objectId = relatedRevocationId;
					if (!isUsedToken(objectId, usedRevocations)) {
						break; // break to create an orphan token
					}
				} else {
					break;
				}
			}
			timestampedObj.setToken(xmlRevocationsMap.get(objectId));
			return timestampedObj;

		case TIMESTAMP:
			timestampedObj.setToken(xmlTimestampsMap.get(objectId));
			return timestampedObj;

		case SIGNED_DATA:
			timestampedObj.setToken(xmlSignedDataMap.get(objectId));
			return timestampedObj;

		default:
			throw new DSSException(String.format("Unsupported category '%s'", timestampReference.getCategory()));

		}

		if (TimestampedObjectType.CERTIFICATE.equals(timestampedObj.getCategory())) {
			timestampedObj.setToken(xmlOrphanCertificateTokensMap.get(objectId));
			timestampedObj.setCategory(TimestampedObjectType.ORPHAN_CERTIFICATE);

		} else if (TimestampedObjectType.REVOCATION.equals(timestampedObj.getCategory())) {
			timestampedObj.setToken(xmlOrphanRevocationTokensMap.get(objectId));
			timestampedObj.setCategory(TimestampedObjectType.ORPHAN_REVOCATION);

		} else {
			throw new DSSException(String.format("The type of object [%s] is not supported for Orphan Tokens!",
					timestampedObj.getCategory()));

		}

		return timestampedObj;
	}

	private <T extends Token> boolean isUsedToken(String tokenId, Collection<T> usedTokens) {
		for (Token token : usedTokens) {
			if (token.getDSSIdAsString().equals(tokenId)) {
				return true;
			}
		}
		return false;
	}

}
