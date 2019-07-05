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

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBElement;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AdapterUtils;
import eu.europa.esig.dss.CRLBinary;
import eu.europa.esig.dss.CertificatePolicy;
import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.IssuerSerialInfo;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.jaxb.diagnostic.ObjectFactory;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificatePolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlContainerInfo;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificates;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundRevocations;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlManifestFile;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanToken;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureProductionPlace;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedOrphanToken;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedRevocationData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedSignerData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.tsl.TLInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyUsageBit;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;
import eu.europa.esig.dss.x509.revocation.RevocationRef;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseBinary;

/**
 * This class is used to build JAXB objects from the DSS model
 * 
 */
public class DiagnosticDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(DiagnosticDataBuilder.class);

	private DSSDocument signedDocument;
	private ContainerInfo containerInfo;
	private List<AdvancedSignature> signatures;
	private Set<CertificateToken> usedCertificates;
	private Map<CertificateToken, Set<CertificateSourceType>> certificateSourceTypes;
	private Set<RevocationToken> usedRevocations;
	private CommonTrustedCertificateSource trustedCertSource;
	private Date validationDate;

	private boolean includeRawCertificateTokens = false;
	private boolean includeRawRevocationData = false;
	private boolean includeRawTimestampTokens = false;
	
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	private Map<String, XmlCertificate> xmlCerts = new HashMap<String, XmlCertificate>();
	private Map<String, XmlRevocation> xmlRevocations = new HashMap<String, XmlRevocation>();
	private Map<String, XmlSignature> xmlSignatures = new HashMap<String, XmlSignature>();
	private Map<String, XmlTimestamp> xmlTimestamps = new HashMap<String, XmlTimestamp>();
	private Map<String, XmlSignerData> xmlSignedData = new HashMap<String, XmlSignerData>();
	private Map<String, XmlOrphanToken> xmlOrphanTokens = new HashMap<String, XmlOrphanToken>();

	// A map between {@link CertificateToken}'s id and its certificate refs
	private Map<String, List<CertificateRef>> certificateRefsMap = new HashMap<String, List<CertificateRef>>();
	// A map between {@link RevocationToken}'s id and its revocation refs
	private Map<String, List<RevocationRef>> revocationRefsMap = new HashMap<String, List<RevocationRef>>();

	/**
	 * This method allows to set the document which is analysed
	 * 
	 * @param signedDocument
	 *                       the document which is analysed
	 * @return the builder
	 */
	public DiagnosticDataBuilder document(DSSDocument signedDocument) {
		this.signedDocument = signedDocument;
		return this;
	}

	/**
	 * This method allows to set the container info (ASiC)
	 * 
	 * @param containerInfo
	 *                      the container information
	 * @return the builder
	 */
	public DiagnosticDataBuilder containerInfo(ContainerInfo containerInfo) {
		this.containerInfo = containerInfo;
		return this;
	}

	/**
	 * This method allows to set the found signatures
	 * 
	 * @param signatures
	 *                   the found signatures
	 * @return the builder
	 */
	public DiagnosticDataBuilder foundSignatures(List<AdvancedSignature> signatures) {
		this.signatures = signatures;
		return this;
	}

	/**
	 * This method allows to set the used certificates
	 * 
	 * @param usedCertificates
	 *                         the used certificates
	 * @return the builder
	 */
	public DiagnosticDataBuilder usedCertificates(Set<CertificateToken> usedCertificates) {
		this.usedCertificates = usedCertificates;
		return this;
	}

	/**
	 * This method allows to set the certificate source types
	 * 
	 * @param certificateSourceTypes
	 *                               the certificate source types
	 * @return the builder
	 */
	public DiagnosticDataBuilder certificateSourceTypes(Map<CertificateToken, Set<CertificateSourceType>> certificateSourceTypes) {
		this.certificateSourceTypes = certificateSourceTypes;
		return this;
	}

	/**
	 * This method allows to set the used revocation data
	 * 
	 * @param usedRevocations
	 *                        the used revocation data
	 * @return the builder
	 */
	public DiagnosticDataBuilder usedRevocations(Set<RevocationToken> usedRevocations) {
		this.usedRevocations = usedRevocations;
		return this;
	}

	/**
	 * This method allows set the behavior to include raw certificate tokens into
	 * the diagnostic report. (default: false)
	 * 
	 * @param includeRawCertificateTokens
	 *                                    true if the certificate tokens need to be
	 *                                    exported in the diagnostic data
	 * @return the builder
	 */
	public DiagnosticDataBuilder includeRawCertificateTokens(boolean includeRawCertificateTokens) {
		this.includeRawCertificateTokens = includeRawCertificateTokens;
		return this;
	}

	/**
	 * This method allows set the behavior to include raw revocation data into the
	 * diagnostic report. (default: false)
	 * 
	 * @param includeRawRevocationData
	 *                                 true if the revocation data need to be
	 *                                 exported in the diagnostic data
	 * @return the builder
	 */
	public DiagnosticDataBuilder includeRawRevocationData(boolean includeRawRevocationData) {
		this.includeRawRevocationData = includeRawRevocationData;
		return this;
	}

	/**
	 * This method allows set the behavior to include raw timestamp tokens into the
	 * diagnostic report. (default: false)
	 * 
	 * @param includeRawTimestampTokens
	 *                                  true if the timestamp tokens need to be
	 *                                  exported in the diagnostic data
	 * @return the builder
	 */
	public DiagnosticDataBuilder includeRawTimestampTokens(boolean includeRawTimestampTokens) {
		this.includeRawTimestampTokens = includeRawTimestampTokens;
		return this;
	}
	
	/**
	 * This method allows to set the default {@link DigestAlgorithm} which will be
	 * used for tokens' DigestAlgoAndValue calculation
	 * 
	 * @param digestAlgorithm
	 *                        {@link DigestAlgorithm} to set as default
	 * @return the builder
	 */
	public DiagnosticDataBuilder setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.defaultDigestAlgorithm = digestAlgorithm;
		return this;
	}

	/**
	 * This method allows to set the TrustedListsCertificateSource
	 * 
	 * @param trustedCertSource
	 *                          the trusted lists certificate source
	 * @return the builder
	 */
	public DiagnosticDataBuilder trustedCertificateSource(CertificateSource trustedCertSource) {
		if (trustedCertSource instanceof CommonTrustedCertificateSource) {
			this.trustedCertSource = (CommonTrustedCertificateSource) trustedCertSource;
		}
		return this;
	}

	/**
	 * This method allows to set the validation date
	 * 
	 * @param validationDate
	 *                       the validation date
	 * @return the builder
	 */
	public DiagnosticDataBuilder validationDate(Date validationDate) {
		this.validationDate = validationDate;
		return this;
	}

	public XmlDiagnosticData build() {
		
		XmlDiagnosticData diagnosticData = new XmlDiagnosticData();
		if (signedDocument != null) {
			diagnosticData.setDocumentName(removeSpecialCharsForXml(signedDocument.getName()));
		}
		diagnosticData.setValidationDate(validationDate);
		diagnosticData.setContainerInfo(getXmlContainerInfo());

		Collection<XmlCertificate> xmlCertificates = buildXmlCertificates();
		diagnosticData.getUsedCertificates().addAll(xmlCertificates);

		Collection<XmlRevocation> xmlRevocations = buildXmlRevocations();
		diagnosticData.getUsedRevocations().addAll(xmlRevocations);

		if (Utils.isCollectionNotEmpty(signatures)) {
			// collect original signer documents
			Collection<XmlSignerData> xmlSignerData = buildXmlSignerData(signatures);
			diagnosticData.getOriginalDocuments().addAll(xmlSignerData);
			
			Collection<XmlSignature> xmlSignatures = buildXmlSignatures(signatures);
			diagnosticData.getSignatures().addAll(xmlSignatures);
			
			Collection<XmlTimestamp> XmlTimestamps = buildXmlTimestamps(signatures);
			diagnosticData.getUsedTimestamps().addAll(XmlTimestamps);
		}
		
		if (Utils.isMapNotEmpty(xmlOrphanTokens)) {
			diagnosticData.getOrphanTokens().addAll(xmlOrphanTokens.values());
		}

		if (trustedCertSource instanceof TrustedListsCertificateSource) {
			TrustedListsCertificateSource tlCS = (TrustedListsCertificateSource) trustedCertSource;

			Collection<XmlTrustedList> xmlTrustedLists = buildXmlTrustedLists(tlCS);
			diagnosticData.getTrustedLists().addAll(xmlTrustedLists);

			TLInfo lotlInfo = tlCS.getLotlInfo();
			if (Utils.isCollectionNotEmpty(xmlTrustedLists) && lotlInfo != null) {
				diagnosticData.setListOfTrustedLists(getXmlTrustedList("LOTL", lotlInfo));
			}

			for (XmlCertificate xmlCert : diagnosticData.getUsedCertificates()) {
				xmlCert.setTrustedServiceProviders(getXmlTrustedServiceProviders(getCertificateToken(xmlCert.getId())));
			}
		}

		return diagnosticData;
	}

	private Collection<XmlCertificate> buildXmlCertificates() {
		if (Utils.isCollectionNotEmpty(usedCertificates)) {
			for (CertificateToken certificateToken : usedCertificates) {
				XmlCertificate currentXmlCet = buildDetachedXmlCertificate(certificateToken);
				xmlCerts.put(certificateToken.getDSSIdAsString(), currentXmlCet);
			}
			for (CertificateToken certificateToken : usedCertificates) {
				XmlCertificate xmlCertificate = xmlCerts.get(certificateToken.getDSSIdAsString());
				xmlCertificate.setSigningCertificate(getXmlSigningCertificate(certificateToken.getPublicKeyOfTheSigner()));
				xmlCertificate.setCertificateChain(getXmlForCertificateChain(certificateToken.getPublicKeyOfTheSigner()));
			}
		}
		return xmlCerts.values();
	}
	
	private Collection<XmlRevocation> buildXmlRevocations() {
		if (Utils.isCollectionNotEmpty(usedRevocations)) {
			for (RevocationToken revocationToken : usedRevocations) {
				if (!xmlRevocations.containsKey(revocationToken.getDSSIdAsString())) {
					XmlRevocation currentXmlRevocation = buildDetachedXmlRevocation(revocationToken);
					currentXmlRevocation.setSigningCertificate(getXmlSigningCertificate(revocationToken.getPublicKeyOfTheSigner()));
					currentXmlRevocation.setCertificateChain(getXmlForCertificateChain(revocationToken.getPublicKeyOfTheSigner()));
					xmlRevocations.put(revocationToken.getDSSIdAsString(), currentXmlRevocation);
				}
			}
			for (CertificateToken certificateToken : usedCertificates) {
				XmlCertificate xmlCertificate = xmlCerts.get(certificateToken.getDSSIdAsString());
				Set<RevocationToken> revocationsForCert = getRevocationsForCert(certificateToken);
				for (RevocationToken revocationToken : revocationsForCert) {
					XmlRevocation xmlRevocation = xmlRevocations.get(revocationToken.getDSSIdAsString());
					XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
					xmlCertificateRevocation.setRevocation(xmlRevocation);
					
					final Boolean revocationTokenStatus = revocationToken.getStatus();
					// revocationTokenStatus can be null when OCSP return Unknown. In this case we
					// set status to false.
					xmlCertificateRevocation.setStatus(revocationTokenStatus == null ? false : revocationTokenStatus);
					xmlCertificateRevocation.setRevocationDate(revocationToken.getRevocationDate());
					CRLReasonEnum reason = revocationToken.getReason();
					if (reason != null) {
						xmlCertificateRevocation.setReason(RevocationReason.valueOf(reason.name()));
					}

					xmlCertificate.getRevocations().add(xmlCertificateRevocation);
				}
			}
		}
		return xmlRevocations.values();
	}
	
	private Collection<XmlSignerData> buildXmlSignerData(List<AdvancedSignature> signatures) {
		List<String> originalDocumentIds = new ArrayList<String>();
		for (AdvancedSignature advancedSignature : signatures) {
			for (SignatureScope signatureScope : advancedSignature.getSignatureScopes()) {
				if (!originalDocumentIds.contains(signatureScope.getDSSIdAsString())) {
					XmlSignerData signedData = getXmlSignerData(signatureScope);
					xmlSignedData.put(signatureScope.getDSSIdAsString(), signedData);
					originalDocumentIds.add(signatureScope.getDSSIdAsString());
				}
			}
		}
		return xmlSignedData.values();
	}
	
	private Collection<XmlSignature> buildXmlSignatures(List<AdvancedSignature> signatures) {
		List<XmlSignature> builtSignatures = new ArrayList<XmlSignature>();
		for (AdvancedSignature advancedSignature : signatures) {
			XmlSignature currentXmlSignature = buildDetachedXmlSignature(advancedSignature);
			xmlSignatures.put(advancedSignature.getId(), currentXmlSignature);
			builtSignatures.add(currentXmlSignature);
		}
		return builtSignatures;
	}
	
	private Collection<XmlTimestamp> buildXmlTimestamps(List<AdvancedSignature> signatures) {
		List<XmlTimestamp> builtTimestamps = new ArrayList<XmlTimestamp>();
		for (AdvancedSignature advancedSignature : signatures) {
			XmlSignature currentSignature = xmlSignatures.get(advancedSignature.getId());
			// build timestamps
			for (XmlTimestamp xmlTimestamp : getXmlTimestamps(advancedSignature)) {
				addXmlTimestampToList(builtTimestamps, xmlTimestamp);
			}
			// attach timestamps
			currentSignature.setFoundTimestamps(getXmlFoundTimestamps(advancedSignature));
			// attach master
			AdvancedSignature masterSignature = advancedSignature.getMasterSignature();
			if (masterSignature != null) {
				XmlSignature xmlMasterSignature = xmlSignatures.get(masterSignature.getId());
				currentSignature.setCounterSignature(true);
				currentSignature.setParent(xmlMasterSignature);
			}
		}
		return builtTimestamps;
	}
	
	private Collection<XmlTrustedList> buildXmlTrustedLists(TrustedListsCertificateSource tlCS) {
		List<XmlTrustedList> trustedLists = new ArrayList<XmlTrustedList>();
		Set<String> countryCodes = new HashSet<String>();
		for (CertificateToken certificateToken : usedCertificates) {
			Set<ServiceInfo> associatedTSPS = trustedCertSource.getTrustServices(certificateToken);
			if (Utils.isCollectionNotEmpty(associatedTSPS)) {
				for (ServiceInfo serviceInfo : associatedTSPS) {
					countryCodes.add(serviceInfo.getTlCountryCode());
				}
			}
		}
		for (String countryCode : countryCodes) {
			TLInfo tlInfo = tlCS.getTlInfo(countryCode);
			if (tlInfo != null) {
				trustedLists.add(getXmlTrustedList(countryCode, tlInfo));
			}
		}
		return trustedLists;
	}

	private XmlTrustedList getXmlTrustedList(String countryCode, TLInfo tlInfo) {
		if (tlInfo != null) {
			XmlTrustedList result = new XmlTrustedList();
			result.setCountryCode(tlInfo.getCountryCode());
			result.setUrl(tlInfo.getUrl());
			result.setIssueDate(tlInfo.getIssueDate());
			result.setNextUpdate(tlInfo.getNextUpdate());
			result.setLastLoading(tlInfo.getLastLoading());
			result.setSequenceNumber(tlInfo.getSequenceNumber());
			result.setVersion(tlInfo.getVersion());
			result.setWellSigned(tlInfo.isWellSigned());
			return result;
		} else {
			LOG.warn("Not info found for country {}", countryCode);
			return null;
		}
	}

	private XmlContainerInfo getXmlContainerInfo() {
		if (containerInfo != null) {
			XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
			xmlContainerInfo.setContainerType(containerInfo.getContainerType().getReadable());
			String zipComment = containerInfo.getZipComment();
			if (Utils.isStringNotBlank(zipComment)) {
				xmlContainerInfo.setZipComment(zipComment);
			}
			xmlContainerInfo.setMimeTypeFilePresent(containerInfo.isMimeTypeFilePresent());
			xmlContainerInfo.setMimeTypeContent(containerInfo.getMimeTypeContent());
			xmlContainerInfo.setContentFiles(containerInfo.getSignedDocumentFilenames());
			xmlContainerInfo.setManifestFiles(getXmlManifests(containerInfo.getManifestFiles()));
			return xmlContainerInfo;
		}
		return null;
	}

	private List<XmlManifestFile> getXmlManifests(List<ManifestFile> manifestFiles) {
		if (Utils.isCollectionNotEmpty(manifestFiles)) {
			List<XmlManifestFile> xmlManifests = new ArrayList<XmlManifestFile>();
			for (ManifestFile manifestFile : manifestFiles) {
				XmlManifestFile xmlManifest = new XmlManifestFile();
				xmlManifest.setFilename(manifestFile.getFilename());
				xmlManifest.setSignatureFilename(manifestFile.getSignatureFilename());
				xmlManifest.getEntries().addAll(manifestFile.getEntries());
				xmlManifests.add(xmlManifest);
			}
			return xmlManifests;
		}
		return null;
	}

	private XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setSignatureFilename(removeSpecialCharsForXml(signature.getSignatureFilename()));

		xmlSignature.setId(signature.getId());
		xmlSignature.setDAIdentifier(signature.getDAIdentifier());
		xmlSignature.setDateTime(signature.getSigningTime());
		xmlSignature.setStructuralValidation(getXmlStructuralValidation(signature));
		xmlSignature.setSignatureFormat(getXmlSignatureFormat(signature.getDataFoundUpToLevel()));

		xmlSignature.setSignatureProductionPlace(getXmlSignatureProductionPlace(signature.getSignatureProductionPlace()));
		xmlSignature.setCommitmentTypeIndication(getXmlCommitmentTypeIndication(signature.getCommitmentTypeIndication()));
		xmlSignature.setClaimedRoles(getXmlClaimedRole(signature.getClaimedSignerRoles()));
		xmlSignature.getCertifiedRoles().addAll(getXmlCertifiedRoles(signature.getCertifiedSignerRoles()));

		xmlSignature.setContentType(signature.getContentType());
		xmlSignature.setMimeType(signature.getMimeType());
		xmlSignature.setContentIdentifier(signature.getContentIdentifier());
		xmlSignature.setContentHints(signature.getContentHints());

		final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {
			xmlSignature.setSigningCertificate(getXmlSigningCertificate(theCertificateValidity));
			CertificateToken signingCertificateToken = theCertificateValidity.getCertificateToken();
			xmlSignature.setCertificateChain(getXmlForCertificateChain(signingCertificateToken.getPublicKey()));
			xmlSignature.setBasicSignature(getXmlBasicSignature(signature, signingCertificateToken));
		}
		xmlSignature.setDigestMatchers(getXmlDigestMatchers(signature));

		xmlSignature.setPolicy(getXmlPolicy(signature));
		xmlSignature.setPDFSignatureDictionary(getXmlPDFSignatureDictionary(signature));
		xmlSignature.setSignerDocumentRepresentations(getXmlSignerDocumentRepresentations(signature));
		
		// TODO: sigRef digest (for etsi SignatureReferenceType)

		xmlSignature.setFoundRevocations(getXmlFoundRevocations(signature));
		xmlSignature.setFoundCertificates(getXmlFoundCertificates(signature));
		xmlSignature.setSignatureScopes(getXmlSignatureScopes(signature.getSignatureScopes()));
		
		xmlSignature.setSignatureValue(signature.getSignatureValue());

		return xmlSignature;
	}

	private XmlPDFSignatureDictionary getXmlPDFSignatureDictionary(AdvancedSignature signature) {
		SignatureForm signatureForm = signature.getSignatureForm();
		if (SignatureForm.PAdES == signatureForm || SignatureForm.PKCS7 == signatureForm) {
			XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
			pdfSignatureDictionary.setSignatureFieldName(emptyToNull(signature.getSignatureFieldName()));
			pdfSignatureDictionary.setSignerName(emptyToNull(signature.getSignerName()));
			pdfSignatureDictionary.setFilter(emptyToNull(signature.getFilter()));
			pdfSignatureDictionary.setSubFilter(emptyToNull(signature.getSubFilter()));
			pdfSignatureDictionary.setContactInfo(emptyToNull(signature.getContactInfo()));
			pdfSignatureDictionary.setReason(emptyToNull(signature.getReason()));
			pdfSignatureDictionary.getSignatureByteRange().addAll(
					AdapterUtils.intArrayToBigIntegerList(signature.getSignatureByteRange()));
			return pdfSignatureDictionary;
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
	
	private XmlSignerData getXmlSignerData(SignatureScope signatureScope) {
		XmlSignerData xmlSignedData = new XmlSignerData();
		xmlSignedData.setId(signatureScope.getDSSIdAsString());
		xmlSignedData.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(signatureScope.getDigest().getAlgorithm(), 
				signatureScope.getDigest().getValue()));
		xmlSignedData.setReferencedName(signatureScope.getName());
		return xmlSignedData;
	}	

	private XmlStructuralValidation getXmlStructuralValidation(AdvancedSignature signature) {
		String structureValidationResult = signature.getStructureValidationResult();
		final XmlStructuralValidation xmlStructuralValidation = new XmlStructuralValidation();
		xmlStructuralValidation.setValid(Utils.isStringEmpty(structureValidationResult));
		if (Utils.isStringNotEmpty(structureValidationResult)) {
			xmlStructuralValidation.setMessage(structureValidationResult);
		}
		return xmlStructuralValidation;
	}

	/**
	 * Escape special characters which cause problems with jaxb or
	 * documentbuilderfactory and namespace aware mode
	 */
	private String removeSpecialCharsForXml(String text) {
		if (Utils.isStringNotEmpty(text)) {
			return text.replaceAll("&", "");
		}
		return Utils.EMPTY_STRING;
	}
	
	private void addXmlTimestampToList(List<XmlTimestamp> timestampList, XmlTimestamp timestampToAdd) {
		boolean contains = false;
		for (XmlTimestamp timestamp : timestampList) {
			if (timestamp.getId().equals(timestampToAdd.getId())) {
				List<JAXBElement<? extends XmlTimestampedObject>> timestampedObjects = timestampToAdd.getTimestampedObjects();
				for (JAXBElement<? extends XmlTimestampedObject> timestampedObject : timestampedObjects) {
					if (!isTimestampContainsReference(timestamp, timestampedObject)) {
						timestamp.getTimestampedObjects().add(timestampedObject);
					}
				}
				contains = true;
			}
		}
		if (!contains) {
			timestampList.add(timestampToAdd);
		}
	}
	
	private boolean isTimestampContainsReference(XmlTimestamp timestamp, JAXBElement<? extends XmlTimestampedObject> timestampedObject) {
		for (JAXBElement<? extends XmlTimestampedObject> oldObject : timestamp.getTimestampedObjects()) {
			if (timestampedObject.getValue().getToken().getId().equals(oldObject.getValue().getToken().getId())) {
				return true;
			}
		}
		return false;
	}

	private XmlRevocation buildDetachedXmlRevocation(RevocationToken revocationToken) {

		final XmlRevocation xmlRevocation = new XmlRevocation();
		xmlRevocation.setId(revocationToken.getDSSIdAsString());
		
		if (isInternalOrigin(revocationToken)) {
			xmlRevocation.setOrigin(XmlRevocationOrigin.SIGNATURE);
		} else {
			XmlRevocationOrigin revocationOriginType = XmlRevocationOrigin.valueOf(revocationToken.getFirstOrigin().name());
			xmlRevocation.setOrigin(revocationOriginType);
		}
		xmlRevocation.setType(RevocationType.valueOf(revocationToken.getRevocationSourceType().name()));

		xmlRevocation.setProductionDate(revocationToken.getProductionDate());
		xmlRevocation.setThisUpdate(revocationToken.getThisUpdate());
		xmlRevocation.setNextUpdate(revocationToken.getNextUpdate());
		xmlRevocation.setExpiredCertsOnCRL(revocationToken.getExpiredCertsOnCRL());
		xmlRevocation.setArchiveCutOff(revocationToken.getArchiveCutOff());

		String sourceURL = revocationToken.getSourceURL();
		if (Utils.isStringNotEmpty(sourceURL)) { // not empty = online
			xmlRevocation.setSourceAddress(sourceURL);
		}

		xmlRevocation.setBasicSignature(getXmlBasicSignature(revocationToken));

		xmlRevocation.setSigningCertificate(getXmlSigningCertificate(revocationToken.getPublicKeyOfTheSigner()));
		xmlRevocation.setCertificateChain(getXmlForCertificateChain(revocationToken.getPublicKeyOfTheSigner()));

		xmlRevocation.setCertHashExtensionPresent(revocationToken.isCertHashPresent());
		xmlRevocation.setCertHashExtensionMatch(revocationToken.isCertHashMatch());

		if (includeRawRevocationData) {
			xmlRevocation.setBase64Encoded(revocationToken.getEncoded());
		} else {
			byte[] revocationDigest = revocationToken.getDigest(defaultDigestAlgorithm);
			xmlRevocation.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, revocationDigest));
		}

		return xmlRevocation;
	}
	
	private boolean isInternalOrigin(RevocationToken revocationToken) {
		for (RevocationOrigin origin : revocationToken.getOrigins()) {
			if (XmlRevocationOrigin.valueOf(origin.name()).isInternalOrigin()) {
				return true;
			}
		}
		return false;
	}

	private List<XmlChainItem> getXmlForCertificateChain(PublicKey certPubKey) {
		if (certPubKey != null) {
			final List<XmlChainItem> certChainTokens = new ArrayList<XmlChainItem>();
			Set<CertificateToken> processedTokens = new HashSet<CertificateToken>();
			CertificateToken issuerToken = getCertificateByPubKey(certPubKey);
			while (issuerToken != null) {
				certChainTokens.add(getXmlChainItem(issuerToken));
				if (issuerToken.isSelfSigned() || processedTokens.contains(issuerToken)) {
					break;
				}
				processedTokens.add(issuerToken);
				issuerToken = getCertificateByPubKey(issuerToken.getPublicKeyOfTheSigner());
			}
			return certChainTokens;
		}
		return null;
	}

	private boolean isTrusted(CertificateToken cert) {
		return trustedCertSource != null && !trustedCertSource.get(cert.getSubjectX500Principal()).isEmpty();
	}

	private XmlChainItem getXmlChainItem(final CertificateToken token) {
		final XmlChainItem chainItem = new XmlChainItem();
		chainItem.setCertificate(xmlCerts.get(token.getDSSIdAsString()));
		return chainItem;
	}

	/**
	 * This method creates the SigningCertificate element for the current token.
	 *
	 * @param token
	 *              the token
	 * @return
	 */
	private XmlSigningCertificate getXmlSigningCertificate(final PublicKey certPubKey) {
		final CertificateToken certificateByPubKey = getCertificateByPubKey(certPubKey);
		if (certificateByPubKey != null) {
			final XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
			xmlSignCertType.setCertificate(xmlCerts.get(certificateByPubKey.getDSSIdAsString()));
			return xmlSignCertType;
		}
		return null;
	}

	private CertificateToken getCertificateByPubKey(final PublicKey certPubKey) {
		if (certPubKey == null) {
			return null;
		}

		List<CertificateToken> founds = new ArrayList<CertificateToken>();
		for (CertificateToken cert : usedCertificates) {
			if (certPubKey.equals(cert.getPublicKey())) {
				founds.add(cert);
				if (isTrusted(cert)) {
					return cert;
				}
			}
		}

		if (Utils.isCollectionNotEmpty(founds)) {
			return founds.iterator().next();
		}
		return null;
	}

	private XmlSigningCertificate getXmlSigningCertificate(CertificateValidity theCertificateValidity) {
		XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
		CertificateToken signingCertificateToken = theCertificateValidity.getCertificateToken();
		if (signingCertificateToken != null) {
			xmlSignCertType.setCertificate(xmlCerts.get(signingCertificateToken.getDSSIdAsString()));
		}
		xmlSignCertType.setAttributePresent(theCertificateValidity.isAttributePresent());
		xmlSignCertType.setDigestValuePresent(theCertificateValidity.isDigestPresent());
		xmlSignCertType.setDigestValueMatch(theCertificateValidity.isDigestEqual());
		final boolean issuerSerialMatch = theCertificateValidity.isSerialNumberEqual() && theCertificateValidity.isDistinguishedNameEqual();
		xmlSignCertType.setIssuerSerialMatch(issuerSerialMatch);
		return xmlSignCertType;
	}

	private XmlSignatureProductionPlace getXmlSignatureProductionPlace(SignatureProductionPlace signatureProductionPlace) {
		if (signatureProductionPlace != null) {
			final XmlSignatureProductionPlace xmlSignatureProductionPlace = new XmlSignatureProductionPlace();
			xmlSignatureProductionPlace.setCountryName(emptyToNull(signatureProductionPlace.getCountryName()));
			xmlSignatureProductionPlace.setStateOrProvince(emptyToNull(signatureProductionPlace.getStateOrProvince()));
			xmlSignatureProductionPlace.setPostalCode(emptyToNull(signatureProductionPlace.getPostalCode()));
			xmlSignatureProductionPlace.setAddress(emptyToNull(signatureProductionPlace.getStreetAddress()));
			xmlSignatureProductionPlace.setCity(emptyToNull(signatureProductionPlace.getCity()));
			return xmlSignatureProductionPlace;
		}
		return null;
	}

	private List<XmlCertifiedRole> getXmlCertifiedRoles(List<CertifiedRole> certifiedRoles) {
		List<XmlCertifiedRole> xmlCertRoles = new ArrayList<XmlCertifiedRole>();
		if (Utils.isCollectionNotEmpty(certifiedRoles)) {
			for (final CertifiedRole certifiedRole : certifiedRoles) {
				final XmlCertifiedRole xmlCertifiedRole = new XmlCertifiedRole();
				xmlCertifiedRole.setCertifiedRole(certifiedRole.getRole());
				xmlCertifiedRole.setNotBefore(certifiedRole.getNotBefore());
				xmlCertifiedRole.setNotAfter(certifiedRole.getNotAfter());
				xmlCertRoles.add(xmlCertifiedRole);
			}
			return xmlCertRoles;
		}
		return Collections.emptyList();
	}

	private List<String> getXmlClaimedRole(String[] claimedRoles) {
		if (Utils.isArrayNotEmpty(claimedRoles)) {
			return Arrays.asList(claimedRoles);
		}
		return Collections.emptyList();
	}

	private List<String> getXmlCommitmentTypeIndication(CommitmentType commitmentTypeIndication) {
		if (commitmentTypeIndication != null) {
			return commitmentTypeIndication.getIdentifiers();
		}
		return Collections.emptyList();
	}

	private String getXmlSignatureFormat(SignatureLevel signatureLevel) {
		return signatureLevel == null ? "UNKNOWN" : signatureLevel.toString();
	}

	private XmlDistinguishedName getXmlDistinguishedName(final String x500PrincipalFormat, final X500Principal X500PrincipalName) {
		final XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat(x500PrincipalFormat);
		xmlDistinguishedName.setValue(X500PrincipalName.getName(x500PrincipalFormat));
		return xmlDistinguishedName;
	}

	private XmlFoundCertificates getXmlFoundCertificates(AdvancedSignature signature) {
		XmlFoundCertificates xmlFoundCertificates = new XmlFoundCertificates();
		xmlFoundCertificates.getRelatedCertificates().addAll(getXmlRelatedCertificates(signature));
		xmlFoundCertificates.getRelatedCertificates().addAll(getXmlRelatedCertificateForOrphanReferences(signature));
		xmlFoundCertificates.getOrphanCertificates().addAll(getOrphanCertificates(signature));
		return xmlFoundCertificates;
	}
	
	private List<XmlRelatedCertificate> getXmlRelatedCertificates(AdvancedSignature signature) {
		Map<String, XmlRelatedCertificate> relatedCertificatesMap = new HashMap<String, XmlRelatedCertificate>();
		SignatureCertificateSource certificateSource = signature.getCertificateSource();
		
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOriginType.KEY_INFO, 
				certificateSource.getKeyInfoCertificates(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOriginType.CERTIFICATE_VALUES, 
				certificateSource.getCertificateValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOriginType.ATTR_AUTORITIES_CERT_VALUES, 
				certificateSource.getAttrAuthoritiesCertValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOriginType.TIMESTAMP_DATA_VALIDATION, 
				certificateSource.getTimeStampValidationDataCertValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOriginType.DSS, 
				certificateSource.getDSSDictionaryCertValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOriginType.VRI, 
				certificateSource.getVRIDictionaryCertValues(), certificateSource);
		
		return new ArrayList<XmlRelatedCertificate>(relatedCertificatesMap.values());
	}
	
	private void populateCertificateOriginMap(Map<String, XmlRelatedCertificate> relatedCertificatesMap, CertificateOriginType origin,
			List<CertificateToken> certificateTokens, SignatureCertificateSource certificateSource) {
		for (CertificateToken certificateToken : certificateTokens) {
			if (!relatedCertificatesMap.containsKey(certificateToken.getDSSIdAsString())) {
				XmlRelatedCertificate xmlFoundCertificate = getXmlRelatedCertificate(origin, certificateToken, certificateSource);
				relatedCertificatesMap.put(certificateToken.getDSSIdAsString(), xmlFoundCertificate);
			} else {
				XmlRelatedCertificate storedFoundCertificate = relatedCertificatesMap.get(certificateToken.getDSSIdAsString());
				if (!storedFoundCertificate.getOrigins().contains(origin)) {
					storedFoundCertificate.getOrigins().add(origin);
				}
			}
		}
	}
	
	private XmlRelatedCertificate getXmlRelatedCertificate(CertificateOriginType origin, CertificateToken cert, SignatureCertificateSource certificateSource) {
		XmlRelatedCertificate xrc = new XmlRelatedCertificate();
		xrc.getOrigins().add(origin);
		xrc.setCertificate(xmlCerts.get(cert.getDSSIdAsString()));
		List<CertificateRef> referencesForCertificateToken = certificateSource.getReferencesForCertificateToken(cert);
		for (CertificateRef certificateRef : referencesForCertificateToken) {
			xrc.getCertificateRefs().add(getXmlCertificateRef(certificateRef));
		}
		certificateRefsMap.put(cert.getDSSIdAsString(), referencesForCertificateToken);
		return xrc;
	}
	
	private XmlCertificateRef getXmlCertificateRef(CertificateRef ref) {
		XmlCertificateRef certificateRef = new XmlCertificateRef();
		IssuerSerialInfo serialInfo = ref.getIssuerInfo();
		if (serialInfo != null && serialInfo.getIssuerName() != null && serialInfo.getSerialNumber() != null) {
			IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(serialInfo.getIssuerName(), serialInfo.getSerialNumber());
			certificateRef.setIssuerSerial(DSSASN1Utils.getDEREncoded(issuerSerial));
		}
		Digest refDigest = ref.getCertDigest();
		if (refDigest != null) {
			certificateRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(refDigest.getAlgorithm(), refDigest.getValue()));
		}
		certificateRef.setOrigin(CertificateRefOriginType.valueOf(ref.getLocation().toString()));
		return certificateRef;
	}
	
	private List<XmlRelatedCertificate> getXmlRelatedCertificateForOrphanReferences(AdvancedSignature signature) {
		List<XmlRelatedCertificate> relatedCertificates = new ArrayList<XmlRelatedCertificate>();
		for (CertificateRef certificateRef : signature.getOrphanCertificateRefs()) {
			Digest certRefDigest = certificateRef.getCertDigest();
			for (CertificateToken certificateToken : usedCertificates) {
				if (Arrays.equals(certRefDigest.getValue(), certificateToken.getDigest(certRefDigest.getAlgorithm()))) {
					relatedCertificates.add(getXmlRelatedCertificate(certificateToken, certificateRef));
				}
			}
		}
		return relatedCertificates;
	}
	
	private XmlRelatedCertificate getXmlRelatedCertificate(CertificateToken cert, CertificateRef certificateRef) {
		XmlRelatedCertificate xrc = new XmlRelatedCertificate();
		xrc.setCertificate(xmlCerts.get(cert.getDSSIdAsString()));
		if (getXmlCertificateSources(cert).contains(XmlCertificateSourceType.TIMESTAMP)) {
			xrc.getOrigins().add(CertificateOriginType.INTERNAL_TIMESTAMP_CERTIFICATE_VALUES);
		}
		xrc.getCertificateRefs().add(getXmlCertificateRef(certificateRef));
		certificateRefsMap.put(cert.getDSSIdAsString(), Arrays.asList(certificateRef));
		return xrc;
	}
	
	private List<XmlOrphanCertificate> getOrphanCertificates(AdvancedSignature signature) {
		List<XmlOrphanCertificate> orphanCertificates = new ArrayList<XmlOrphanCertificate>();
		
		for (CertificateToken certificateToken : signature.getCertificates()) {
			if (!usedCertificates.contains(certificateToken)) {
				orphanCertificates.add(createXmlOrphanCertificate(certificateToken, false));
			}
		}
		for (CertificateToken certificateToken : signature.getTimestampSource().getCertificates()) {
			if (!usedCertificates.contains(certificateToken)) {
				orphanCertificates.add(createXmlOrphanCertificate(certificateToken, true));
			}
		}
		
		List<CertificateRef> orphanCertificateRefs = signature.getOrphanCertificateRefs();
		for (List<CertificateRef> assignedCertificateRefs : certificateRefsMap.values()) {
			orphanCertificateRefs.removeAll(assignedCertificateRefs);
		} 
		
		for (CertificateRef orphanCertificateRef : orphanCertificateRefs) {
			orphanCertificates.add(createXmlOrphanCertificate(orphanCertificateRef));
		}
		
		return orphanCertificates;
	}
	
	private XmlOrphanCertificate createXmlOrphanCertificate(CertificateToken certificateToken, boolean foundInTimestamp) {
		XmlOrphanCertificate orphanCertificate = new XmlOrphanCertificate();
		if (foundInTimestamp || getXmlCertificateSources(certificateToken).contains(XmlCertificateSourceType.TIMESTAMP)) {
			orphanCertificate.getOrigins().add(CertificateOriginType.INTERNAL_TIMESTAMP_CERTIFICATE_VALUES);
		}
		orphanCertificate.setToken(createXmlOrphanCertificateToken(certificateToken));
		return orphanCertificate;
	}
	
	private XmlOrphanCertificate createXmlOrphanCertificate(CertificateRef orphanCertificateRef) {
		XmlOrphanCertificate orphanCertificate = new XmlOrphanCertificate();
		orphanCertificate.setToken(createXmlOrphanCertificateToken(orphanCertificateRef));
		orphanCertificate.getCertificateRefs().add(getXmlCertificateRef(orphanCertificateRef));
		return orphanCertificate;
	}
	
	private XmlOrphanToken createXmlOrphanCertificateToken(CertificateToken certificateToken) {
		XmlOrphanToken orphanToken = new XmlOrphanToken();
		orphanToken.setId(certificateToken.getDSSIdAsString());
		orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, certificateToken.getDigest(defaultDigestAlgorithm)));
		orphanToken.setType(OrphanTokenType.CERTIFICATE);
		xmlOrphanTokens.put(certificateToken.getDSSIdAsString(), orphanToken);
		return orphanToken;
	}
	
	private XmlOrphanToken createXmlOrphanCertificateToken(CertificateRef orphanCertificateRef) {
		XmlOrphanToken orphanToken = new XmlOrphanToken();
		orphanToken.setId(orphanCertificateRef.getDSSIdAsString());
		orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(orphanCertificateRef.getCertDigest()));
		orphanToken.setType(OrphanTokenType.CERTIFICATE);
		xmlOrphanTokens.put(orphanCertificateRef.getDSSIdAsString(), orphanToken);
		return orphanToken;
	}

	private List<XmlTimestamp> getXmlTimestamps(AdvancedSignature signature) {
		List<XmlTimestamp> xmlTimestamps = new ArrayList<XmlTimestamp>();
		xmlTimestamps.addAll(getXmlTimestamps(signature.getAllTimestamps()));
		return xmlTimestamps;
	}
	
	private List<XmlFoundTimestamp> getXmlFoundTimestamps(AdvancedSignature signature) {
		List<XmlFoundTimestamp> foundTimestamps = new ArrayList<XmlFoundTimestamp>();
		foundTimestamps.addAll(getFoundTimestamps(signature.getAllTimestamps()));
		return foundTimestamps;
	}

	private List<XmlFoundTimestamp> getFoundTimestamps(List<TimestampToken> tsts) {
		List<XmlFoundTimestamp> foundTimestamps = new ArrayList<XmlFoundTimestamp>();
		for (TimestampToken timestampToken : tsts) {
			XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
			foundTimestamp.setTimestamp(xmlTimestamps.get(timestampToken.getDSSIdAsString()));
			if (timestampToken.getTimestampLocation() != null) {
				foundTimestamp.setLocation(XmlTimestampLocation.valueOf(timestampToken.getTimestampLocation().name()));
			}
			foundTimestamps.add(foundTimestamp);
		}
		return foundTimestamps;
	}
	
	private XmlFoundRevocations getXmlFoundRevocations(AdvancedSignature signature) {
		XmlFoundRevocations foundRevocations = new XmlFoundRevocations();
		foundRevocations.getRelatedRevocations().addAll(getXmlRelatedRevocations(signature));

		List<EncapsulatedRevocationTokenIdentifier> orphanRevocations = getOrphanRevocations(signature);
		if (Utils.isCollectionNotEmpty(orphanRevocations)) {
			foundRevocations.getOrphanRevocations().addAll(getXmlOrphanRevocations(orphanRevocations, signature));
		}

		for (RevocationRef leftRevocationRef : signature.getOrphanRevocationRefs()) {
			XmlOrphanRevocation revocationFromRef = createOrphanRevocationFromRef(leftRevocationRef);
			foundRevocations.getOrphanRevocations().add(revocationFromRef);
		}
		return foundRevocations;
	}
	
	private List<EncapsulatedRevocationTokenIdentifier> getOrphanRevocations(AdvancedSignature signature) {
		List<EncapsulatedRevocationTokenIdentifier> orphanIdentifiers = new ArrayList<EncapsulatedRevocationTokenIdentifier>();
		List<EncapsulatedRevocationTokenIdentifier> revocationIdentifiers = signature.getAllFoundRevocationIdentifiers();
		for (EncapsulatedRevocationTokenIdentifier revocationIdentifier : revocationIdentifiers) {
			if (!xmlRevocations.containsKey(revocationIdentifier.asXmlId())) {
				orphanIdentifiers.add(revocationIdentifier);
			}
		}
		return orphanIdentifiers;
	}

	private List<XmlRelatedRevocation> getXmlRelatedRevocations(AdvancedSignature signature) {
		List<XmlRelatedRevocation> xmlRelatedRevocations = new ArrayList<XmlRelatedRevocation>();
		xmlRelatedRevocations.addAll(getXmlRevocationsByType(signature, signature.getAllRevocationTokens()));
		return xmlRelatedRevocations;
	}

	private List<XmlRelatedRevocation> getXmlRevocationsByType(AdvancedSignature signature, Collection<RevocationToken> revocationTokens) {
		List<XmlRelatedRevocation> xmlRelatedRevocations = new ArrayList<XmlRelatedRevocation>();
		Set<String> revocationKeys = new HashSet<String>();
		for (RevocationToken revocationToken : revocationTokens) {
			if (!revocationKeys.contains(revocationToken.getDSSIdAsString())) {
				XmlRevocation xmlRevocation = xmlRevocations.get(revocationToken.getDSSIdAsString());
				if (xmlRevocation != null) {
					XmlRelatedRevocation xmlRelatedRevocation = new XmlRelatedRevocation();
					xmlRelatedRevocation.setRevocation(xmlRevocation);
					xmlRelatedRevocation.setType(RevocationType.valueOf(revocationToken.getRevocationSourceType().name()));
					for (RevocationOrigin origin : revocationToken.getOrigins()) {
						xmlRelatedRevocation.getOrigins().add(XmlRevocationOrigin.valueOf(origin.toString()));
					}
					List<RevocationRef> revocationRefs = signature.findRefsForRevocationToken(revocationToken);
					if (Utils.isCollectionNotEmpty(revocationRefs)) {
						xmlRelatedRevocation.getRevocationRefs().addAll(getXmlRevocationRefs(revocationRefs));
					}

					xmlRelatedRevocations.add(xmlRelatedRevocation);
					revocationKeys.add(revocationToken.getDSSIdAsString());
					revocationRefsMap.put(revocationToken.getDSSIdAsString(), revocationRefs);
				}
			}
		}
		return xmlRelatedRevocations;
	}

	private List<XmlRevocationRef> getXmlRevocationRefs(List<RevocationRef> revocationRefs) {
		List<XmlRevocationRef> xmlRevocationRefs = new ArrayList<XmlRevocationRef>();
		for (RevocationRef ref : revocationRefs) {
			XmlRevocationRef revocationRef;
			if (ref instanceof CRLRef) {
				revocationRef = getXmlCRLRevocationRef((CRLRef) ref);
			} else {
				revocationRef = getXmlOCSPRevocationRef((OCSPRef) ref);
			}
			xmlRevocationRefs.add(revocationRef);
		}
		return xmlRevocationRefs;
	}
	
	private XmlRevocationRef getXmlCRLRevocationRef(CRLRef crlRef) {
		XmlRevocationRef xmlRevocationRef = new XmlRevocationRef();
		xmlRevocationRef.setOrigin(XmlRevocationRefOrigin.valueOf(crlRef.getOrigin().toString()));
		if (crlRef.getDigest() != null) {
			xmlRevocationRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(crlRef.getDigest()));
		}
		return xmlRevocationRef;
	}
	
	private XmlRevocationRef getXmlOCSPRevocationRef(OCSPRef ocspRef) {
		XmlRevocationRef xmlRevocationRef = new XmlRevocationRef();
		xmlRevocationRef.setOrigin(XmlRevocationRefOrigin.valueOf(ocspRef.getOrigin().toString()));
		if (ocspRef.getDigest() != null) {
			xmlRevocationRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(ocspRef.getDigest()));
		}
		xmlRevocationRef.setProducedAt(ocspRef.getProducedAt());
		String name = ocspRef.getResponderId().getName();
		if (Utils.isStringNotEmpty(name)) {
			xmlRevocationRef.setResponderIdName(name);
		}
		byte[] key = ocspRef.getResponderId().getKey();
		if (Utils.isArrayNotEmpty(key)) {
			xmlRevocationRef.setResponderIdKey(key);
		}
		return xmlRevocationRef;
	}
	
	private List<XmlOrphanRevocation> getXmlOrphanRevocations(Collection<EncapsulatedRevocationTokenIdentifier> orphanRevocations, AdvancedSignature signature) {
		List<XmlOrphanRevocation> xmlOrphanRevocations = new ArrayList<XmlOrphanRevocation>();
		for (EncapsulatedRevocationTokenIdentifier revocationIdentifier : orphanRevocations) {
			xmlOrphanRevocations.add(getXmlOrphanRevocation(revocationIdentifier, signature));
		}
		return xmlOrphanRevocations;
	}
	
	private XmlOrphanRevocation getXmlOrphanRevocation(EncapsulatedRevocationTokenIdentifier revocationIdentifier, AdvancedSignature signature) {
		XmlOrphanRevocation xmlOrphanRevocation = new XmlOrphanRevocation();
		xmlOrphanRevocation.setToken(createOrphanTokenFromRevocationIdentifier(revocationIdentifier));
		if (revocationIdentifier instanceof CRLBinary) {
			xmlOrphanRevocation.setType(RevocationType.CRL);
			for (RevocationOrigin origin : signature.getCompleteCRLSource().getRevocationOrigins((CRLBinary) revocationIdentifier)) {
				xmlOrphanRevocation.getOrigins().add(XmlRevocationOrigin.valueOf(origin.name()));
			}
		} else {
			xmlOrphanRevocation.setType(RevocationType.OCSP);
			for (RevocationOrigin origin : signature.getCompleteOCSPSource().getRevocationOrigins((OCSPResponseBinary) revocationIdentifier)) {
				xmlOrphanRevocation.getOrigins().add(XmlRevocationOrigin.valueOf(origin.name()));
			}
		}
		List<RevocationRef> refsForRevocationToken = signature.findRefsForRevocationIdentifier(revocationIdentifier);
		for (RevocationRef revocationRef : refsForRevocationToken) {
			xmlOrphanRevocation.getRevocationRefs().add(revocationRefToXml(revocationRef));
		}
		revocationRefsMap.put(revocationIdentifier.asXmlId(), refsForRevocationToken);
		return xmlOrphanRevocation;
	}
	
	private XmlRevocationRef revocationRefToXml(RevocationRef ref) {
		XmlRevocationRef xmlRevocationRef;
		if (ref instanceof CRLRef) {
			xmlRevocationRef = getXmlCRLRevocationRef((CRLRef) ref);
		} else {
			xmlRevocationRef = getXmlOCSPRevocationRef((OCSPRef) ref);
		}
		return xmlRevocationRef;
	}
	
	private XmlOrphanToken createOrphanTokenFromRevocationIdentifier(EncapsulatedRevocationTokenIdentifier revocationIdentifier) {
		XmlOrphanToken orphanToken = new XmlOrphanToken();
		String tokenId = revocationIdentifier.asXmlId();
		orphanToken.setId(tokenId);
		orphanToken.setType(OrphanTokenType.REVOCATION);
		if (includeRawRevocationData) {
			orphanToken.setBase64Encoded(revocationIdentifier.getBinaries());
		} else {
			byte[] digestValue = revocationIdentifier.getDigestValue(defaultDigestAlgorithm);
			orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, digestValue));
		}
		if (!xmlOrphanTokens.containsKey(tokenId)) {
			xmlOrphanTokens.put(tokenId, orphanToken);
		}
		return orphanToken;
	}
	
	private XmlOrphanRevocation createOrphanRevocationFromRef(RevocationRef ref) {
		XmlOrphanRevocation xmlOrphanRevocation = new XmlOrphanRevocation();
		
		XmlOrphanToken orphanToken = new XmlOrphanToken();
		orphanToken.setId(ref.getDSSIdAsString());
		orphanToken.setType(OrphanTokenType.REVOCATION);
		orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(ref.getDigest()));
		xmlOrphanTokens.put(ref.getDSSIdAsString(), orphanToken);
		
		xmlOrphanRevocation.setToken(orphanToken);
		if (ref instanceof CRLRef) {
			xmlOrphanRevocation.setType(RevocationType.CRL);
		} else {
			xmlOrphanRevocation.setType(RevocationType.OCSP);
		}
		xmlOrphanRevocation.getRevocationRefs().add(revocationRefToXml(ref));
		return xmlOrphanRevocation;
	}

	/**
	 * This method deals with the signature policy. The retrieved information is
	 * transformed to the JAXB object.
	 *
	 * @param signaturePolicy
	 *                        The Signature Policy
	 * 
	 */
	private XmlPolicy getXmlPolicy(AdvancedSignature signature) {
		SignaturePolicy signaturePolicy = signature.getPolicyId();
		if (signaturePolicy == null) {
			return null;
		}

		final XmlPolicy xmlPolicy = new XmlPolicy();

		final String policyId = signaturePolicy.getIdentifier();
		xmlPolicy.setId(policyId);

		final String policyUrl = signaturePolicy.getUrl();
		xmlPolicy.setUrl(policyUrl);
		
		final String description = signaturePolicy.getDescription();
		xmlPolicy.setDescription(description);

		final String notice = signaturePolicy.getNotice();
		xmlPolicy.setNotice(notice);

		final byte[] digestValue = signaturePolicy.getDigestValue();
		final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();

		if (Utils.isArrayNotEmpty(digestValue)) {
			xmlPolicy.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(signPolicyHashAlgFromSignature, digestValue));
		}

		try {
			SignaturePolicyValidator validator = null;
			ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
			Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

			if (validatorOptions.hasNext()) {
				for (SignaturePolicyValidator signaturePolicyValidator : loader) {
					signaturePolicyValidator.setSignature(signature);
					if (signaturePolicyValidator.canValidate()) {
						validator = signaturePolicyValidator;
						break;
					}
				}
			}

			if (validator == null) {
				// if not empty and no other implementation is found for ASN1 signature policies
				validator = new BasicASNSignaturePolicyValidator();
				validator.setSignature(signature);
			}

			validator.validate();
			xmlPolicy.setAsn1Processable(validator.isAsn1Processable());
			xmlPolicy.setDigestAlgorithmsEqual(validator.isDigestAlgorithmsEqual());
			xmlPolicy.setIdentified(validator.isIdentified());
			xmlPolicy.setStatus(validator.isStatus());
			xmlPolicy.setProcessingError(validator.getProcessingErrors());
		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.getMessage());
			// Do nothing
			LOG.warn(e.getMessage(), e);
		}
		return xmlPolicy;
	}

	private List<XmlTimestamp> getXmlTimestamps(List<TimestampToken> timestamps) {
		List<XmlTimestamp> xmlTimestampsList = new ArrayList<XmlTimestamp>();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampToken timestampToken : timestamps) {
				XmlTimestamp xmlTimestamp = getXmlTimestamp(timestampToken);
				xmlTimestampsList.add(xmlTimestamp);
				xmlTimestamps.put(xmlTimestamp.getId(), xmlTimestamp);
			}
		}
		return xmlTimestampsList;
	}

	private XmlTimestamp getXmlTimestamp(final TimestampToken timestampToken) {

		final XmlTimestamp xmlTimestampToken = new XmlTimestamp();

		xmlTimestampToken.setId(timestampToken.getDSSIdAsString());
		xmlTimestampToken.setType(XmlTimestampType.valueOf(timestampToken.getTimeStampType().name()));
		xmlTimestampToken.setProductionTime(timestampToken.getGenerationTime());
		xmlTimestampToken.setDigestMatcher(getXmlDigestMatcher(timestampToken));
		xmlTimestampToken.setBasicSignature(getXmlBasicSignature(timestampToken));

		xmlTimestampToken.setSigningCertificate(getXmlSigningCertificate(timestampToken.getPublicKeyOfTheSigner()));
		xmlTimestampToken.setCertificateChain(getXmlForCertificateChain(timestampToken.getPublicKeyOfTheSigner()));
		xmlTimestampToken.setTimestampedObjects(getXmlTimestampedObjects(timestampToken));

		if (includeRawTimestampTokens) {
			xmlTimestampToken.setBase64Encoded(timestampToken.getEncoded());
		} else {
			byte[] certDigest = timestampToken.getDigest(defaultDigestAlgorithm);
			xmlTimestampToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, certDigest));
		}

		return xmlTimestampToken;
	}

	private XmlDigestMatcher getXmlDigestMatcher(TimestampToken timestampToken) {
		XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
		digestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
		DigestAlgorithm digestAlgo = timestampToken.getSignedDataDigestAlgo();
		digestMatcher.setDigestMethod(digestAlgo == null ? "" : digestAlgo.getName());
		digestMatcher.setDigestValue(timestampToken.getMessageImprintDigest());
		digestMatcher.setDataFound(timestampToken.isMessageImprintDataFound());
		digestMatcher.setDataIntact(timestampToken.isMessageImprintDataIntact());
		return digestMatcher;
	}

	private List<JAXBElement<? extends XmlTimestampedObject>> getXmlTimestampedObjects(TimestampToken timestampToken) {
		List<TimestampedReference> timestampReferences = timestampToken.getTimestampedReferences();
		if (Utils.isCollectionNotEmpty(timestampReferences)) {
			ObjectFactory objectFactory = new ObjectFactory();
			List<JAXBElement<? extends XmlTimestampedObject>> objects = new ArrayList<JAXBElement<? extends XmlTimestampedObject>>();
			for (final TimestampedReference timestampReference : timestampReferences) {
				XmlTimestampedObject xmlTimestampedObject = createXmlTimestampedObject(timestampReference);
				if (xmlTimestampedObject instanceof XmlTimestampedSignature) {
					objects.add(objectFactory.createTimestampedSignature((XmlTimestampedSignature)xmlTimestampedObject));
				} else if (xmlTimestampedObject instanceof XmlTimestampedCertificate) {
					objects.add(objectFactory.createTimestampedCertificate((XmlTimestampedCertificate)xmlTimestampedObject));
				} else if (xmlTimestampedObject instanceof XmlTimestampedRevocationData) {
					objects.add(objectFactory.createTimestampedRevocationData((XmlTimestampedRevocationData)xmlTimestampedObject));
				} else if (xmlTimestampedObject instanceof XmlTimestampedTimestamp) {
					objects.add(objectFactory.createTimestampedTimestamp((XmlTimestampedTimestamp)xmlTimestampedObject));
				} else if (xmlTimestampedObject instanceof XmlTimestampedSignerData) {
					objects.add(objectFactory.createTimestampedSignerData((XmlTimestampedSignerData)xmlTimestampedObject));
				}else if (xmlTimestampedObject instanceof XmlTimestampedOrphanToken) {
					objects.add(objectFactory.createTimestampedOrphanToken((XmlTimestampedOrphanToken)xmlTimestampedObject));
				}
			}
			return objects;
		}
		return null;
	}
	
	private XmlTimestampedObject createXmlTimestampedObject(final TimestampedReference timestampReference) {
		String objectId = timestampReference.getObjectId();
		switch (timestampReference.getCategory()) {
			case SIGNATURE:
				XmlTimestampedSignature sigRef = new XmlTimestampedSignature();
				sigRef.setToken(xmlSignatures.get(objectId));
				return sigRef;
			case CERTIFICATE:
				if (!isUsedToken(objectId, usedCertificates))
					break;
				XmlTimestampedCertificate certRef = new XmlTimestampedCertificate();
				certRef.setToken(xmlCerts.get(objectId));
				return certRef;
			case REVOCATION:
				if (!isUsedToken(objectId, usedRevocations))
					break;
				XmlTimestampedRevocationData revocRef = new XmlTimestampedRevocationData();
				revocRef.setToken(xmlRevocations.get(objectId));
				return revocRef;
			case TIMESTAMP:
				XmlTimestampedTimestamp tstRef = new XmlTimestampedTimestamp();
				tstRef.setToken(xmlTimestamps.get(objectId));
				return tstRef;
			case SIGNED_DATA:
				XmlTimestampedSignerData sdRef = new XmlTimestampedSignerData();
				sdRef.setToken(xmlSignedData.get(objectId));
				return sdRef;
			default:
				throw new DSSException("Unsupported category " + timestampReference.getCategory());
		}
		XmlTimestampedOrphanToken orphanRef = new XmlTimestampedOrphanToken();
		orphanRef.setToken(xmlOrphanTokens.get(objectId));
		return orphanRef;
	}
	
	private <T extends Token> boolean isUsedToken(String tokenId, Collection<T> usedTokens) {
		for (Token token : usedTokens) {
			if (token.getDSSIdAsString().equals(tokenId)) {
				return true;
			}
		}
		return false;
	}

	private XmlBasicSignature getXmlBasicSignature(final Token token) {
		final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();

		SignatureAlgorithm signatureAlgorithm = token.getSignatureAlgorithm();
		if (signatureAlgorithm != null) {
			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm().getName());
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm().getName());
			MaskGenerationFunction maskGenerationFunction = signatureAlgorithm.getMaskGenerationFunction();
			if (maskGenerationFunction != null) {
				xmlBasicSignatureType.setMaskGenerationFunctionUsedToSignThisToken(maskGenerationFunction.name());
			}
		}
		xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(DSSPKUtils.getPublicKeySize(token));

		final boolean signatureValid = token.isSignatureValid();
		xmlBasicSignatureType.setSignatureIntact(signatureValid);
		xmlBasicSignatureType.setSignatureValid(signatureValid);
		return xmlBasicSignatureType;
	}

	private List<String> getXmlKeyUsages(List<KeyUsageBit> keyUsageBits) {
		final List<String> xmlKeyUsageBitItems = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(keyUsageBits)) {
			for (final KeyUsageBit keyUsageBit : keyUsageBits) {
				xmlKeyUsageBitItems.add(keyUsageBit.name());
			}
		}
		return xmlKeyUsageBitItems;
	}

	private XmlBasicSignature getXmlBasicSignature(AdvancedSignature signature, CertificateToken signingCertificateToken) {
		XmlBasicSignature xmlBasicSignature = new XmlBasicSignature();

		final EncryptionAlgorithm encryptionAlgorithm = signature.getEncryptionAlgorithm();
		final String encryptionAlgorithmString = encryptionAlgorithm == null ? "?" : encryptionAlgorithm.getName();
		xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmString);

		final int keyLength = signingCertificateToken == null ? 0 : DSSPKUtils.getPublicKeySize(signingCertificateToken.getPublicKey());
		xmlBasicSignature.setKeyLengthUsedToSignThisToken(String.valueOf(keyLength));
		final DigestAlgorithm digestAlgorithm = signature.getDigestAlgorithm();
		final String digestAlgorithmString = digestAlgorithm == null ? "?" : digestAlgorithm.getName();
		xmlBasicSignature.setDigestAlgoUsedToSignThisToken(digestAlgorithmString);
		MaskGenerationFunction maskGenerationFunction = signature.getMaskGenerationFunction();
		if (maskGenerationFunction != null) {
			xmlBasicSignature.setMaskGenerationFunctionUsedToSignThisToken(maskGenerationFunction.name());
		}

		SignatureCryptographicVerification scv = signature.getSignatureCryptographicVerification();
		xmlBasicSignature.setSignatureIntact(scv.isSignatureIntact());
		xmlBasicSignature.setSignatureValid(scv.isSignatureValid());
		return xmlBasicSignature;
	}

	private List<XmlDigestMatcher> getXmlDigestMatchers(AdvancedSignature signature) {
		List<XmlDigestMatcher> refs = new ArrayList<XmlDigestMatcher>();
		List<ReferenceValidation> refValidations = signature.getReferenceValidations();
		for (ReferenceValidation referenceValidation : refValidations) {
			refs.add(getXmlDigestMatcher(referenceValidation));
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
			DigestAlgorithm algorithm = digest.getAlgorithm();
			ref.setDigestMethod(algorithm != null ? algorithm.getName() : "?");
		}
		ref.setDataFound(referenceValidation.isFound());
		ref.setDataIntact(referenceValidation.isIntact());
		return ref;
	}

	private List<XmlSignatureScope> getXmlSignatureScopes(List<SignatureScope> scopes) {
		List<XmlSignatureScope> xmlScopes = new ArrayList<XmlSignatureScope>();
		if (Utils.isCollectionNotEmpty(scopes)) {
			for (SignatureScope xmlSignatureScope : scopes) {
				xmlScopes.add(getXmlSignatureScope(xmlSignatureScope));
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
		xmlSignatureScope.setSignerData(xmlSignedData.get(scope.getDSSIdAsString()));
		return xmlSignatureScope;
	}

	private XmlCertificate buildDetachedXmlCertificate(CertificateToken certToken) {

		final XmlCertificate xmlCert = new XmlCertificate();

		xmlCert.setId(certToken.getDSSIdAsString());

		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.CANONICAL, certToken.getSubjectX500Principal()));
		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, certToken.getSubjectX500Principal()));

		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.CANONICAL, certToken.getIssuerX500Principal()));
		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, certToken.getIssuerX500Principal()));

		xmlCert.setSerialNumber(certToken.getSerialNumber());

		X500Principal x500Principal = certToken.getSubjectX500Principal();
		xmlCert.setCommonName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, x500Principal));
		xmlCert.setLocality(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.L, x500Principal));
		xmlCert.setState(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.ST, x500Principal));
		xmlCert.setCountryName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, x500Principal));
		xmlCert.setOrganizationName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, x500Principal));
		xmlCert.setGivenName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.GIVENNAME, x500Principal));
		xmlCert.setOrganizationalUnit(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.OU, x500Principal));
		xmlCert.setSurname(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.SURNAME, x500Principal));
		xmlCert.setPseudonym(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.PSEUDONYM, x500Principal));
		xmlCert.setEmail(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.E, x500Principal));

		xmlCert.setAuthorityInformationAccessUrls(DSSASN1Utils.getCAAccessLocations(certToken));
		xmlCert.setOCSPAccessUrls(DSSASN1Utils.getOCSPAccessLocations(certToken));
		xmlCert.setCRLDistributionPoints(DSSASN1Utils.getCrlUrls(certToken));
		
		xmlCert.setSources(getXmlCertificateSources(certToken));

		xmlCert.setNotAfter(certToken.getNotAfter());
		xmlCert.setNotBefore(certToken.getNotBefore());
		final PublicKey publicKey = certToken.getPublicKey();
		xmlCert.setPublicKeySize(DSSPKUtils.getPublicKeySize(publicKey));
		xmlCert.setPublicKeyEncryptionAlgo(EncryptionAlgorithm.forKey(publicKey).getName());

		xmlCert.setKeyUsageBits(getXmlKeyUsages(certToken.getKeyUsageBits()));
		xmlCert.setExtendedKeyUsages(getXmlOids(DSSASN1Utils.getExtendedKeyUsage(certToken)));

		xmlCert.setIdPkixOcspNoCheck(DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken));

		xmlCert.setBasicSignature(getXmlBasicSignature(certToken));

		xmlCert.setQCStatementIds(getXmlOids(DSSASN1Utils.getQCStatementsIdList(certToken)));
		xmlCert.setQCTypes(getXmlOids(DSSASN1Utils.getQCTypesIdList(certToken)));
		xmlCert.setCertificatePolicies(getXmlCertificatePolicies(DSSASN1Utils.getCertificatePolicies(certToken)));

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(isTrusted(certToken));

		if (includeRawCertificateTokens) {
			xmlCert.setBase64Encoded(certToken.getEncoded());
		} else {
			byte[] certDigest = certToken.getDigest(defaultDigestAlgorithm);
			xmlCert.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, certDigest));
		}

		return xmlCert;
	}

	private List<XmlCertificateSourceType> getXmlCertificateSources(final CertificateToken token) {
		List<XmlCertificateSourceType> certificateSources = new ArrayList<XmlCertificateSourceType>();
		if (certificateSourceTypes != null) {
			Set<CertificateSourceType> sourceTypes = certificateSourceTypes.get(token);
			if (sourceTypes != null) {
				for (CertificateSourceType source : sourceTypes) {
					certificateSources.add(XmlCertificateSourceType.valueOf(source.name()));
				}
			}
		}
		if (Utils.isCollectionEmpty(certificateSources)) {
			certificateSources.add(XmlCertificateSourceType.UNKNOWN);
		}
		return certificateSources;
	}

	private CertificateToken getCertificateToken(String certificateId) {
		for (CertificateToken certificateToken : usedCertificates) {
			if (Utils.areStringsEqual(certificateId, certificateToken.getDSSIdAsString())) {
				return certificateToken;
			}
		}
		return null;
	}

	private Set<RevocationToken> getRevocationsForCert(CertificateToken certToken) {
		Set<RevocationToken> revocations = new HashSet<RevocationToken>();
		if (Utils.isCollectionNotEmpty(usedRevocations)) {
			for (RevocationToken revocationToken : usedRevocations) {
				if (Utils.areStringsEqual(certToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())) {
					revocations.add(revocationToken);
				}
			}
		}
		return revocations;
	}

	private List<XmlCertificatePolicy> getXmlCertificatePolicies(List<CertificatePolicy> certificatePolicies) {
		List<XmlCertificatePolicy> result = new ArrayList<XmlCertificatePolicy>();
		for (CertificatePolicy cp : certificatePolicies) {
			XmlCertificatePolicy xmlCP = new XmlCertificatePolicy();
			xmlCP.setValue(cp.getOid());
			xmlCP.setDescription(OidRepository.getDescription(cp.getOid()));
			xmlCP.setCpsUrl(cp.getCpsUrl());
			result.add(xmlCP);
		}
		return result;
	}

	private List<XmlOID> getXmlOids(List<String> oidList) {
		List<XmlOID> result = new ArrayList<XmlOID>();
		if (Utils.isCollectionNotEmpty(oidList)) {
			for (String oid : oidList) {
				XmlOID xmlOID = new XmlOID();
				xmlOID.setValue(oid);
				xmlOID.setDescription(OidRepository.getDescription(oid));
				result.add(xmlOID);
			}
		}
		return result;
	}

	private List<XmlTrustedServiceProvider> getXmlTrustedServiceProviders(CertificateToken certToken) {
		List<XmlTrustedServiceProvider> result = new ArrayList<XmlTrustedServiceProvider>();
		Map<CertificateToken, Set<ServiceInfo>> servicesByTrustedCert = getRelatedTrustServices(certToken);
		for (Entry<CertificateToken, Set<ServiceInfo>> entry : servicesByTrustedCert.entrySet()) {
			CertificateToken trustedCert = entry.getKey();
			Set<ServiceInfo> services = entry.getValue();

			Map<String, List<ServiceInfo>> servicesByProviders = classifyByServiceProvider(services);
			for (List<ServiceInfo> servicesByProvider : servicesByProviders.values()) {
				ServiceInfo first = servicesByProvider.get(0);
				XmlTrustedServiceProvider serviceProvider = new XmlTrustedServiceProvider();
				serviceProvider.setCountryCode(first.getTlCountryCode());
				serviceProvider.setTSPName(first.getTspName());
				serviceProvider.setTSPRegistrationIdentifier(first.getTspRegistrationIdentifier());
				serviceProvider.setTrustedServices(getXmlTrustedServices(servicesByProvider, certToken, trustedCert));
				result.add(serviceProvider);
			}
		}
		return Collections.unmodifiableList(result);
	}

	private Map<CertificateToken, Set<ServiceInfo>> getRelatedTrustServices(CertificateToken certToken) {
		if (trustedCertSource instanceof TrustedListsCertificateSource) {
			Map<CertificateToken, Set<ServiceInfo>> result = new HashMap<CertificateToken, Set<ServiceInfo>>();
			Set<CertificateToken> processedTokens = new HashSet<CertificateToken>();
			while (certToken != null) {
				Set<ServiceInfo> trustServices = trustedCertSource.getTrustServices(certToken);
				if (!trustServices.isEmpty()) {
					result.put(certToken, trustServices);
				}
				if (certToken.isSelfSigned() || processedTokens.contains(certToken)) {
					break;
				}
				processedTokens.add(certToken);
				certToken = getCertificateByPubKey(certToken.getPublicKeyOfTheSigner());
			}
			return result;
		} else {
			return Collections.emptyMap();
		}
	}

	private List<XmlTrustedService> getXmlTrustedServices(List<ServiceInfo> serviceInfos, CertificateToken certToken, CertificateToken trustedCert) {
		List<XmlTrustedService> result = new ArrayList<XmlTrustedService>();
		for (ServiceInfo serviceInfo : serviceInfos) {
			List<ServiceInfoStatus> serviceStatusAfterOfEqualsCertIssuance = serviceInfo.getStatus().getAfter(certToken.getNotBefore());
			if (Utils.isCollectionNotEmpty(serviceStatusAfterOfEqualsCertIssuance)) {
				for (ServiceInfoStatus serviceInfoStatus : serviceStatusAfterOfEqualsCertIssuance) {
					XmlTrustedService trustedService = new XmlTrustedService();

					trustedService.setServiceDigitalIdentifier(xmlCerts.get(trustedCert.getDSSIdAsString()));
					trustedService.setServiceName(serviceInfoStatus.getServiceName());
					trustedService.setServiceType(serviceInfoStatus.getType());
					trustedService.setStatus(serviceInfoStatus.getStatus());
					trustedService.setStartDate(serviceInfoStatus.getStartDate());
					trustedService.setEndDate(serviceInfoStatus.getEndDate());

					List<String> qualifiers = getQualifiers(serviceInfoStatus, certToken);
					if (Utils.isCollectionNotEmpty(qualifiers)) {
						trustedService.setCapturedQualifiers(qualifiers);
					}

					List<String> additionalServiceInfoUris = serviceInfoStatus.getAdditionalServiceInfoUris();
					if (Utils.isCollectionNotEmpty(additionalServiceInfoUris)) {
						trustedService.setAdditionalServiceInfoUris(additionalServiceInfoUris);
					}

					List<String> serviceSupplyPoints = serviceInfoStatus.getServiceSupplyPoints();
					if (Utils.isCollectionNotEmpty(serviceSupplyPoints)) {
						trustedService.setServiceSupplyPoints(serviceSupplyPoints);
					}

					trustedService.setExpiredCertsRevocationInfo(serviceInfoStatus.getExpiredCertsRevocationInfo());

					result.add(trustedService);
				}
			}
		}
		return Collections.unmodifiableList(result);
	}

	private Map<String, List<ServiceInfo>> classifyByServiceProvider(Set<ServiceInfo> services) {
		Map<String, List<ServiceInfo>> servicesByProviders = new HashMap<String, List<ServiceInfo>>();
		if (Utils.isCollectionNotEmpty(services)) {
			for (ServiceInfo serviceInfo : services) {
				String tradeName = serviceInfo.getTspTradeName();
				List<ServiceInfo> servicesByProvider = servicesByProviders.get(tradeName);
				if (servicesByProvider == null) {
					servicesByProvider = new ArrayList<ServiceInfo>();
					servicesByProviders.put(tradeName, servicesByProvider);
				}
				servicesByProvider.add(serviceInfo);
			}
		}
		return servicesByProviders;
	}

	/**
	 * Retrieves all the qualifiers for which the corresponding conditionEntry is
	 * true.
	 *
	 * @param certificateToken
	 * @return
	 */
	private List<String> getQualifiers(ServiceInfoStatus serviceInfoStatus, CertificateToken certificateToken) {
		LOG.trace("--> GET_QUALIFIERS()");
		List<String> list = new ArrayList<String>();
		final Map<String, List<Condition>> qualifiersAndConditions = serviceInfoStatus.getQualifiersAndConditions();
		for (Entry<String, List<Condition>> conditionEntry : qualifiersAndConditions.entrySet()) {
			List<Condition> conditions = conditionEntry.getValue();
			LOG.trace("  --> {}", conditions);
			for (final Condition condition : conditions) {
				if (condition.check(certificateToken)) {
					LOG.trace("    --> CONDITION TRUE / {}", conditionEntry.getKey());
					list.add(conditionEntry.getKey());
					break;
				}
			}
		}
		return list;

	}
	
	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(Digest digest) {
		if (digest == null) {
			return getXmlDigestAlgoAndValue(null, null);
		} else {
			return getXmlDigestAlgoAndValue(digest.getAlgorithm(), digest.getValue());
		}
	}

	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(DigestAlgorithm digestAlgo, byte[] digestValue) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digestAlgo == null ? "" : digestAlgo.getName());
		xmlDigestAlgAndValue.setDigestValue(digestValue == null ? DSSUtils.EMPTY_BYTE_ARRAY : digestValue);
		return xmlDigestAlgAndValue;
	}

	private String emptyToNull(String text) {
		if (Utils.isStringEmpty(text)) {
			return null;
		}
		return text;
	}

}
