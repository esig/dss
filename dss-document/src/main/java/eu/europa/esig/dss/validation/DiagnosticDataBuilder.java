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

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIssuerSerial;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanTokens;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Info;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Role;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureProductionPlace;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.enumerations.TokenExtractionStategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.TokenComparator;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.spi.x509.CertificateIdentifier;
import eu.europa.esig.dss.spi.x509.CertificatePolicy;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateTokenRefMatcher;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.PSD2QcType;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.RoleOfPSP;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.BasicASNSignaturePolicyValidator;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampTokenComparator;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

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
	private Set<RevocationToken<Revocation>> usedRevocations;
	private Set<TimestampToken> usedTimestamps;
	private ListCertificateSource trustedCertSources = new ListCertificateSource();
	private Date validationDate;
	
	// Merged revocation data sources;
	private ListRevocationSource<CRL> commonCRLSource = new ListRevocationSource<CRL>();
	private ListRevocationSource<OCSP> commonOCSPSource = new ListRevocationSource<OCSP>();

	private TokenExtractionStategy tokenExtractionStategy = TokenExtractionStategy.NONE;
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	private Map<String, XmlCertificate> xmlCertsMap = new HashMap<>();
	private Map<String, XmlRevocation> xmlRevocationsMap = new HashMap<>();
	private Map<String, XmlSignature> xmlSignaturesMap = new HashMap<>();
	private Map<String, XmlTimestamp> xmlTimestampsMap = new HashMap<>();
	private Map<String, XmlSignerData> xmlSignedDataMap = new HashMap<>();
	private Map<String, XmlOrphanCertificateToken> xmlOrphanCertificateTokensMap = new HashMap<>();
	private Map<String, XmlOrphanRevocationToken> xmlOrphanRevocationTokensMap = new HashMap<>();
	private Map<String, XmlTrustedList> xmlTrustedListsMap = new HashMap<>();
	
	// A map between references ids and their related token ids (used to map references for timestamped refs)
	private Map<String, String> referenceMap = new HashMap<>();
	
	private Map<String, CertificateToken> signingCertificateMap = new HashMap<>();

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
	public DiagnosticDataBuilder usedRevocations(Set<RevocationToken<Revocation>> usedRevocations) {
		this.usedRevocations = usedRevocations;
		return this;
	}
	
	/**
	 * This method allows to set the timestamps
	 * 
	 * @param usedTimestamps
	 *                       a set of validated {@link TimestampToken}s
	 * @return the builder
	 */
	public DiagnosticDataBuilder usedTimestamps(Set<TimestampToken> usedTimestamps) {
		this.usedTimestamps = usedTimestamps;
		return this;
	}

	/**
	 * This method allows to set the {@link TokenExtractionStategy} to follow for
	 * the token extraction
	 * 
	 * @param tokenExtractionStategy {@link TokenExtractionStategy} to use
	 * @return the builder
	 */
	public DiagnosticDataBuilder tokenExtractionStategy(TokenExtractionStategy tokenExtractionStategy) {
		this.tokenExtractionStategy = tokenExtractionStategy;
		return this;
	}

	/**
	 * This method allows to set the default {@link DigestAlgorithm} which will be
	 * used for tokens' DigestAlgoAndValue calculation
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm} to set as default
	 * @return the builder
	 */
	public DiagnosticDataBuilder setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.defaultDigestAlgorithm = digestAlgorithm;
		return this;
	}

	/**
	 * This method allows to set the TrustedListsCertificateSources
	 * 
	 * @param trustedCertSources
	 *                          the list of trusted lists certificate sources
	 * @return the builder
	 */
	public DiagnosticDataBuilder trustedCertificateSources(ListCertificateSource trustedCertSources) {
		if (trustedCertSources.areAllCertSourcesTrusted()) {
			this.trustedCertSources = trustedCertSources;
		} else {
			throw new DSSException("Trusted CertificateSource must contain only sources of type TRUSTED_STORE or TRUSTED_LIST!");
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
	
	/**
	 * Sets a merged CRL Source
	 * 
	 * @param completeCRLSource {@link ListRevocationSource} computed from existing
	 *                          sources
	 * @return the builder
	 */
	public DiagnosticDataBuilder completeCRLSource(ListRevocationSource<CRL> completeCRLSource) {
		this.commonCRLSource = completeCRLSource;
		return this;
	}
	
	/**
	 * Sets a merged OCSP Source
	 * 
	 * @param completeOCSPSource {@link ListRevocationSource} computed from existing
	 *                           sources
	 * @return the builder
	 */
	public DiagnosticDataBuilder completeOCSPSource(ListRevocationSource<OCSP> completeOCSPSource) {
		this.commonOCSPSource = completeOCSPSource;
		return this;
	}

	public XmlDiagnosticData build() {
		
		XmlDiagnosticData diagnosticData = new XmlDiagnosticData();
		if (signedDocument != null) {
			diagnosticData.setDocumentName(removeSpecialCharsForXml(signedDocument.getName()));
		}
		diagnosticData.setValidationDate(validationDate);
		diagnosticData.setContainerInfo(getXmlContainerInfo());

		Collection<XmlCertificate> xmlCertificates = buildXmlCertificates(usedCertificates);
		diagnosticData.getUsedCertificates().addAll(xmlCertificates);
		linkSigningCertificateAndChains(usedCertificates);

		Collection<XmlRevocation> xmlRevocations = buildXmlRevocations(usedRevocations);
		diagnosticData.getUsedRevocations().addAll(xmlRevocations);
		
		linkCertificatesAndRevocations(usedCertificates);

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
		
		if (Utils.isMapNotEmpty(xmlOrphanCertificateTokensMap) || Utils.isMapNotEmpty(xmlOrphanRevocationTokensMap)) {
			diagnosticData.setOrphanTokens(buildXmlOrphanTokens());
		}
		
		// timestamped objects must be linked after building of orphan tokens
		if (Utils.isCollectionNotEmpty(usedTimestamps)) {
			linkTimestampsAndTimestampsObjects(usedTimestamps);
		}

		if (isUseTrustedLists()) {
			Collection<XmlTrustedList> trustedLists = buildXmlTrustedLists(trustedCertSources);
			diagnosticData.getTrustedLists().addAll(trustedLists);
			linkCertificatesAndTrustServices(usedCertificates);
		}

		return diagnosticData;
	}

	private boolean isUseTrustedLists() {
		if (!trustedCertSources.isEmpty()) {
			for (CertificateSource certificateSource : trustedCertSources.getSources()) {
				if (certificateSource instanceof TrustedListsCertificateSource) {
					return true;
				}
			}
		}
		return false;
	}

	private void linkTimestampsAndTimestampsObjects(Set<TimestampToken> timestamps) {
		for (TimestampToken timestampToken : timestamps) {
			XmlTimestamp xmlTimestampToken = xmlTimestampsMap.get(timestampToken.getDSSIdAsString());
			xmlTimestampToken.setTimestampedObjects(getXmlTimestampedObjects(timestampToken));
		}
	}

	private Collection<XmlCertificate> buildXmlCertificates(Set<CertificateToken> certificates) {
		List<XmlCertificate> builtCertificates = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(certificates)) {
			List<CertificateToken> tokens = new ArrayList<>(certificates);
			Collections.sort(tokens, new TokenComparator());
			for (CertificateToken certificateToken : tokens) {
				String id = certificateToken.getDSSIdAsString();
				XmlCertificate xmlCertificate = xmlCertsMap.get(id);
				if (xmlCertificate == null) {
					xmlCertificate = buildDetachedXmlCertificate(certificateToken);
					xmlCertsMap.put(id, xmlCertificate);
				}
				builtCertificates.add(xmlCertificate);
			}
		}
		return builtCertificates;
	}
	
	private void linkSigningCertificateAndChains(Set<CertificateToken> certificates) {
		if (Utils.isCollectionNotEmpty(certificates)) {
			for (CertificateToken certificateToken : certificates) {
				XmlCertificate xmlCertificate = xmlCertsMap.get(certificateToken.getDSSIdAsString());
				xmlCertificate.setSigningCertificate(getXmlSigningCertificate(certificateToken));
				xmlCertificate.setCertificateChain(getXmlForCertificateChain(certificateToken));
			}
		}
	}

	private void linkCertificatesAndTrustServices(Set<CertificateToken> certificates) {
		if (Utils.isCollectionNotEmpty(certificates)) {
			for (CertificateToken certificateToken : certificates) {
				XmlCertificate xmlCertificate = xmlCertsMap.get(certificateToken.getDSSIdAsString());
				xmlCertificate.setTrustedServiceProviders(getXmlTrustedServiceProviders(certificateToken));
			}
		}
	}

	private Collection<XmlRevocation> buildXmlRevocations(Set<RevocationToken<Revocation>> revocations) {
		List<XmlRevocation> builtRevocations = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(revocations)) {
			List<RevocationToken<Revocation>> tokens = new ArrayList<>(revocations);
			Collections.sort(tokens, new TokenComparator());
			List<String> uniqueIds = new ArrayList<>(); // CRL can contain multiple entries
			for (RevocationToken<Revocation> revocationToken : tokens) {
				String id = revocationToken.getDSSIdAsString();
				if (uniqueIds.contains(id)) {
					continue;
				}
				XmlRevocation xmlRevocation = xmlRevocationsMap.get(id);
				if (xmlRevocation == null) {
					xmlRevocation = buildDetachedXmlRevocation(revocationToken);
					xmlRevocationsMap.put(id, xmlRevocation);
					builtRevocations.add(xmlRevocation);
				}
				uniqueIds.add(id);
			}
		}
		return builtRevocations;
	}

	private void linkCertificatesAndRevocations(Set<CertificateToken> certificates) {
		if (Utils.isCollectionNotEmpty(certificates)) {
			for (CertificateToken certificateToken : certificates) {
				XmlCertificate xmlCertificate = xmlCertsMap.get(certificateToken.getDSSIdAsString());
				Set<RevocationToken<Revocation>> revocationsForCert = getRevocationsForCert(certificateToken);
				for (RevocationToken<Revocation> revocationToken : revocationsForCert) {
					XmlRevocation xmlRevocation = xmlRevocationsMap.get(revocationToken.getDSSIdAsString());
					XmlCertificateRevocation xmlCertificateRevocation = new XmlCertificateRevocation();
					xmlCertificateRevocation.setRevocation(xmlRevocation);
					xmlCertificateRevocation.setStatus(revocationToken.getStatus());
					xmlCertificateRevocation.setRevocationDate(revocationToken.getRevocationDate());
					xmlCertificateRevocation.setReason(revocationToken.getReason());
					xmlCertificate.getRevocations().add(xmlCertificateRevocation);
				}
			}
		}
	}
	
	private Collection<XmlSignerData> buildXmlSignerDataList(Collection<AdvancedSignature> signatures, Collection<TimestampToken> timestamps) {
		List<String> addedSignedDataIds = new ArrayList<>();
		List<XmlSignerData> signerDataList = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature signature : signatures) {
				if (Utils.isCollectionNotEmpty(signature.getSignatureScopes())) {
					for (SignatureScope signatureScope : signature.getSignatureScopes()) {
						if (!addedSignedDataIds.contains(signatureScope.getDSSIdAsString())) {
							XmlSignerData xmlSignerData = buildXmlSignerData(signatureScope);
							signerDataList.add(xmlSignerData);
							addedSignedDataIds.add(signatureScope.getDSSIdAsString());
						}
					}
				}
			}
		}
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampToken timestampToken : timestamps) {
				if (Utils.isCollectionNotEmpty(timestampToken.getTimestampScopes())) {
					for (SignatureScope signatureScope : timestampToken.getTimestampScopes()) {
						if (!addedSignedDataIds.contains(signatureScope.getDSSIdAsString())) {
							XmlSignerData xmlSignerData = buildXmlSignerData(signatureScope);
							signerDataList.add(xmlSignerData);
							addedSignedDataIds.add(signatureScope.getDSSIdAsString());
						}
					}
				}
			}
		}
		return signerDataList;
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
	
	private Collection<XmlSignature> buildXmlSignatures(List<AdvancedSignature> signatures) {
		List<XmlSignature> builtSignatures = new ArrayList<>();
		for (AdvancedSignature advancedSignature : signatures) {
			String id = advancedSignature.getId();
			XmlSignature xmlSignature = xmlSignaturesMap.get(id);
			if (xmlSignature == null) {
				xmlSignature = buildDetachedXmlSignature(advancedSignature);
				xmlSignaturesMap.put(id, xmlSignature);
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
	
	private void linkSignaturesAndTimestamps(List<AdvancedSignature> signatures) {
		for (AdvancedSignature advancedSignature : signatures) {
			XmlSignature currentSignature = xmlSignaturesMap.get(advancedSignature.getId());
			// attach timestamps
			currentSignature.setFoundTimestamps(getXmlFoundTimestamps(advancedSignature));
		}
	}

	private Collection<XmlTrustedList> buildXmlTrustedLists(ListCertificateSource trustedCertificateSources) {
		List<XmlTrustedList> trustedLists = new ArrayList<>();

		Map<Identifier, XmlTrustedList> mapTrustedLists = new HashMap<>();
		Map<Identifier, XmlTrustedList> mapListOfTrustedLists = new HashMap<>();

		for (CertificateSource certificateSource : trustedCertificateSources.getSources()) {
			if (certificateSource instanceof TrustedListsCertificateSource) {
				TrustedListsCertificateSource tlCertSource = (TrustedListsCertificateSource) certificateSource;
				TLValidationJobSummary summary = tlCertSource.getSummary();
				if (summary != null) {
					Set<Identifier> tlIdentifiers = getTLIdentifiers(tlCertSource);
					for (Identifier tlId : tlIdentifiers) {
						if (!mapTrustedLists.containsKey(tlId)) {
							TLInfo tlInfoById = summary.getTLInfoById(tlId);
							if (tlInfoById != null) {
								mapTrustedLists.put(tlId, getXmlTrustedList(tlInfoById));
							}
						}
					}

					Set<Identifier> lotlIdentifiers = getLOTLIdentifiers(tlCertSource);
					for (Identifier lotlId : lotlIdentifiers) {
						if (!mapListOfTrustedLists.containsKey(lotlId)) {
							LOTLInfo lotlInfoById = summary.getLOTLInfoById(lotlId);
							if (lotlInfoById != null) {
								mapTrustedLists.put(lotlId, getXmlTrustedList(lotlInfoById));
							}
						}
					}

				} else {
					LOG.warn("The TrustedListsCertificateSource does not contain TLValidationJobSummary. TLValidationJob is not performed!");
				}
			}
		}

		trustedLists.addAll(mapTrustedLists.values());
		trustedLists.addAll(mapListOfTrustedLists.values());
		return trustedLists;
	}

	private Set<Identifier> getTLIdentifiers(TrustedListsCertificateSource tlCS) {
		Set<Identifier> tlIdentifiers = new HashSet<>();
		for (CertificateToken certificateToken : usedCertificates) {
			List<TrustProperties> trustServices = tlCS.getTrustServices(certificateToken);
			for (TrustProperties trustProperties : trustServices) {
				tlIdentifiers.add(trustProperties.getTLIdentifier());
			}
		}
		return tlIdentifiers;
	}

	private Set<Identifier> getLOTLIdentifiers(TrustedListsCertificateSource tlCS) {
		Set<Identifier> lotlIdentifiers = new HashSet<>();
		for (CertificateToken certificateToken : usedCertificates) {
			List<TrustProperties> trustServices = tlCS.getTrustServices(certificateToken);
			for (TrustProperties trustProperties : trustServices) {
				Identifier lotlUrl = trustProperties.getLOTLIdentifier();
				if (lotlUrl != null) {
					lotlIdentifiers.add(lotlUrl);
				}
			}
		}
		return lotlIdentifiers;
	}

	private XmlTrustedList getXmlTrustedList(TLInfo tlInfo) {
		String id = tlInfo.getIdentifier().asXmlId();
		XmlTrustedList result = xmlTrustedListsMap.get(id);
		if (result == null) {
			result = new XmlTrustedList();
			if (tlInfo instanceof LOTLInfo) {
				result.setLOTL(true);
			}
			result.setId(id);
			result.setUrl(tlInfo.getUrl());
			ParsingInfoRecord parsingCacheInfo = tlInfo.getParsingCacheInfo();
			if (parsingCacheInfo != null) {
				result.setCountryCode(parsingCacheInfo.getTerritory());
				result.setIssueDate(parsingCacheInfo.getIssueDate());
				result.setNextUpdate(parsingCacheInfo.getNextUpdateDate());
				result.setSequenceNumber(parsingCacheInfo.getSequenceNumber());
				result.setVersion(parsingCacheInfo.getVersion());
			}
			DownloadInfoRecord downloadCacheInfo = tlInfo.getDownloadCacheInfo();
			if (downloadCacheInfo != null) {
				result.setLastLoading(downloadCacheInfo.getLastSuccessSynchronizationTime());
			}
			ValidationInfoRecord validationCacheInfo = tlInfo.getValidationCacheInfo();
			if (validationCacheInfo != null) {
				result.setWellSigned(validationCacheInfo.isValid());
			}
			xmlTrustedListsMap.put(id, result);
		}
		return result;
	}

	private XmlContainerInfo getXmlContainerInfo() {
		if (containerInfo != null) {
			XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
			xmlContainerInfo.setContainerType(containerInfo.getContainerType());
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
			List<XmlManifestFile> xmlManifests = new ArrayList<>();
			for (ManifestFile manifestFile : manifestFiles) {
				XmlManifestFile xmlManifest = new XmlManifestFile();
				xmlManifest.setFilename(manifestFile.getFilename());
				xmlManifest.setSignatureFilename(manifestFile.getSignatureFilename());
				for (ManifestEntry entry : manifestFile.getEntries()) {
					xmlManifest.getEntries().add(entry.getFileName());
				}
				xmlManifests.add(xmlManifest);
			}
			return xmlManifests;
		}
		return null;
	}

	private XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = new XmlSignature();
		if (hasDuplicate(signature)) {
			xmlSignature.setDuplicated(true);
		}
		xmlSignature.setSignatureFilename(removeSpecialCharsForXml(signature.getSignatureFilename()));

		xmlSignature.setId(signature.getId());
		xmlSignature.setDAIdentifier(signature.getDAIdentifier());
		xmlSignature.setClaimedSigningTime(signature.getSigningTime());
		xmlSignature.setStructuralValidation(getXmlStructuralValidation(signature));
		xmlSignature.setSignatureFormat(signature.getDataFoundUpToLevel());

		xmlSignature.setSignatureProductionPlace(getXmlSignatureProductionPlace(signature.getSignatureProductionPlace()));
		xmlSignature.getCommitmentTypeIndications().addAll(getXmlCommitmentTypeIndications(signature.getCommitmentTypeIndications()));
		xmlSignature.getSignerRole().addAll(getXmlSignerRoles(signature.getSignerRoles()));

		xmlSignature.setContentType(signature.getContentType());
		xmlSignature.setMimeType(signature.getMimeType());
		xmlSignature.setContentIdentifier(signature.getContentIdentifier());
		xmlSignature.setContentHints(signature.getContentHints());

		final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		
		PublicKey signingCertificatePublicKey = null;
		if (theCertificateValidity != null) {
			xmlSignature.setSigningCertificate(getXmlSigningCertificate(signature.getDSSId(), theCertificateValidity));
			signingCertificatePublicKey = theCertificateValidity.getPublicKey();
			xmlSignature.setCertificateChain(getXmlForCertificateChain(signingCertificatePublicKey));
		}
		
		xmlSignature.setBasicSignature(getXmlBasicSignature(signature, signingCertificatePublicKey));
		xmlSignature.setDigestMatchers(getXmlDigestMatchers(signature));

		xmlSignature.setPolicy(getXmlPolicy(signature));
		xmlSignature.setSignerInformationStore(getXmlSignerInformationStore(signature.getSignerInformationStoreInfos()));
		xmlSignature.setPDFRevision(getXmlPDFRevision(signature.getPdfRevision()));
		xmlSignature.setSignatureDigestReference(getXmlSignatureDigestReference(signature));
		
		xmlSignature.setSignerDocumentRepresentations(getXmlSignerDocumentRepresentations(signature));

		xmlSignature.setFoundCertificates(getXmlFoundCertificates(signature.getDSSId(), signature.getCertificateSource()));
		xmlSignature.setFoundRevocations(getXmlFoundRevocations(signature.getCRLSource(), signature.getOCSPSource()));
		
		xmlSignature.setSignatureScopes(getXmlSignatureScopes(signature.getSignatureScopes()));
		
		xmlSignature.setSignatureValue(signature.getSignatureValue());

		return xmlSignature;
	}
	
	private boolean hasDuplicate(AdvancedSignature currentSignature) {
		for (AdvancedSignature signature : signatures) {
			if (currentSignature != signature && currentSignature.getId().equals(signature.getId())) {
				return true;
			}
		}
		return false;
	}
	
	private XmlPDFRevision getXmlPDFRevision(PdfRevision pdfRevision) {
		if (pdfRevision != null) {
			XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
			xmlPDFRevision.getSignatureFieldName().addAll(pdfRevision.getFieldNames());
			xmlPDFRevision.setPDFSignatureDictionary(getXmlPDFSignatureDictionary(pdfRevision.getPdfSigDictInfo()));
			return xmlPDFRevision;
		}
		return null;
	}
	
	private List<XmlSignerInfo> getXmlSignerInformationStore(Set<CertificateIdentifier> certificateIdentifiers) {
		if (Utils.isCollectionNotEmpty(certificateIdentifiers)) {
			List<XmlSignerInfo> signerInfos = new ArrayList<>();
			for (CertificateIdentifier certificateIdentifier : certificateIdentifiers) {
				signerInfos.add(getXmlSignerInfo(certificateIdentifier));
			}
			return signerInfos;
		}
		return null;
	}
	
	private XmlSignerInfo getXmlSignerInfo(CertificateIdentifier certificateIdentifier) {
		XmlSignerInfo xmlSignerInfo = new XmlSignerInfo();
		if (certificateIdentifier.getIssuerName() != null) {
			xmlSignerInfo.setIssuerName(certificateIdentifier.getIssuerName().toString());
		}
		xmlSignerInfo.setSerialNumber(certificateIdentifier.getSerialNumber());
		xmlSignerInfo.setSki(certificateIdentifier.getSki());
		if (certificateIdentifier.isCurrent()) {
			xmlSignerInfo.setCurrent(certificateIdentifier.isCurrent());
		}
		return xmlSignerInfo;
	}
	
	private XmlSignerInfo getXmlSignerInfo(ResponderId responderId) {
		XmlSignerInfo xmlSignerInfo = new XmlSignerInfo();
		if (responderId.getX500Principal() != null) {
			xmlSignerInfo.setIssuerName(responderId.getX500Principal().toString());
		}
		xmlSignerInfo.setSki(responderId.getSki());
		return xmlSignerInfo;
	}

	private XmlPDFSignatureDictionary getXmlPDFSignatureDictionary(PdfSignatureDictionary pdfSigDict) {
		if (pdfSigDict != null) {
			XmlPDFSignatureDictionary pdfSignatureDictionary = new XmlPDFSignatureDictionary();
			pdfSignatureDictionary.setSignerName(emptyToNull(pdfSigDict.getSignerName()));
			pdfSignatureDictionary.setType(emptyToNull(pdfSigDict.getType()));
			pdfSignatureDictionary.setFilter(emptyToNull(pdfSigDict.getFilter()));
			pdfSignatureDictionary.setSubFilter(emptyToNull(pdfSigDict.getSubFilter()));
			pdfSignatureDictionary.setContactInfo(emptyToNull(pdfSigDict.getContactInfo()));
			pdfSignatureDictionary.setReason(emptyToNull(pdfSigDict.getReason()));
			pdfSignatureDictionary.getSignatureByteRange().addAll(pdfSigDict.getByteRange().toBigIntegerList());
			return pdfSignatureDictionary;
		}
		return null;
	}

	private XmlSignatureDigestReference getXmlSignatureDigestReference(AdvancedSignature signature) {
		SignatureDigestReference signatureDigestReference = signature.getSignatureDigestReference(defaultDigestAlgorithm);
		if (signatureDigestReference != null) {
			XmlSignatureDigestReference xmlDigestReference = new XmlSignatureDigestReference();
			xmlDigestReference.setCanonicalizationMethod(signatureDigestReference.getCanonicalizationMethod());
			xmlDigestReference.setDigestMethod(signatureDigestReference.getDigestAlgorithm());
			xmlDigestReference.setDigestValue(signatureDigestReference.getDigestValue());
			return xmlDigestReference;
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
			return text.replace("&", "");
		}
		return Utils.EMPTY_STRING;
	}
	
	private List<XmlTimestamp> buildXmlTimestamps(Set<TimestampToken> timestamps) {
		List<XmlTimestamp> xmlTimestampsList = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			List<TimestampToken> tokens = new ArrayList<>(timestamps);
			Collections.sort(tokens, new TimestampTokenComparator());
			for (TimestampToken timestampToken : tokens) {
				String id = timestampToken.getDSSIdAsString();
				XmlTimestamp xmlTimestamp = buildDetachedXmlTimestamp(timestampToken);
				xmlTimestampsMap.put(id, xmlTimestamp);
				xmlTimestampsList.add(xmlTimestamp);
			}
		}
		return xmlTimestampsList;
	}
	
	private XmlOrphanTokens buildXmlOrphanTokens() {
		XmlOrphanTokens xmlOrphanTokens = new XmlOrphanTokens();
		if (Utils.isMapNotEmpty(xmlOrphanCertificateTokensMap)) {
			xmlOrphanTokens.getOrphanCertificates().addAll(xmlOrphanCertificateTokensMap.values());
		}
		buildOrphanRevocationTokensFromCommonSources(); // necessary to collect all data from DSS PDF revisions
		if (Utils.isMapNotEmpty(xmlOrphanRevocationTokensMap)) {
			xmlOrphanTokens.getOrphanRevocations().addAll(xmlOrphanRevocationTokensMap.values());
		}
		return xmlOrphanTokens;
	}
	
	private void buildOrphanRevocationTokensFromCommonSources() {
		for (EncapsulatedRevocationTokenIdentifier revocationIdentifier : commonCRLSource.getAllRevocationBinaries()) {
			String id = revocationIdentifier.asXmlId();
			if (!xmlRevocationsMap.containsKey(id) && !xmlOrphanRevocationTokensMap.containsKey(id)) {
				createOrphanTokenFromRevocationIdentifier(revocationIdentifier);
			}
		}
		for (EncapsulatedRevocationTokenIdentifier revocationIdentifier : commonOCSPSource.getAllRevocationBinaries()) {
			String id = revocationIdentifier.asXmlId();
			if (!xmlRevocationsMap.containsKey(id) && !xmlOrphanRevocationTokensMap.containsKey(id)) {
				createOrphanTokenFromRevocationIdentifier(revocationIdentifier);
			}
		}
	}
	
	private XmlRevocation buildDetachedXmlRevocation(RevocationToken<Revocation> revocationToken) {

		final XmlRevocation xmlRevocation = new XmlRevocation();
		xmlRevocation.setId(revocationToken.getDSSIdAsString());
		
		if (revocationToken.isInternal()) {
			xmlRevocation.setOrigin(RevocationOrigin.INPUT_DOCUMENT);
		} else {
			xmlRevocation.setOrigin(revocationToken.getExternalOrigin());
		}
		xmlRevocation.setType(revocationToken.getRevocationType());

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

		xmlRevocation.setSigningCertificate(getXmlSigningCertificate(revocationToken));
		xmlRevocation.setCertificateChain(getXmlForCertificateChain(revocationToken));

		xmlRevocation.setCertHashExtensionPresent(revocationToken.isCertHashPresent());
		xmlRevocation.setCertHashExtensionMatch(revocationToken.isCertHashMatch());

		if (revocationToken.getCertificateSource() != null) {
			// in case of OCSP token
			xmlRevocation.setFoundCertificates(getXmlFoundCertificates(revocationToken.getDSSId(), revocationToken.getCertificateSource()));
		}

		if (tokenExtractionStategy.isRevocationData()) {
			xmlRevocation.setBase64Encoded(revocationToken.getEncoded());
		} else {
			byte[] revocationDigest = revocationToken.getDigest(defaultDigestAlgorithm);
			xmlRevocation.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, revocationDigest));
		}

		return xmlRevocation;
	}
	
	private List<XmlChainItem> getXmlForCertificateChain(final PublicKey publicKey) {
		if (publicKey != null) {
			CertificateToken certificateByPubKey = getCertificateByPubKey(publicKey);
			if (certificateByPubKey != null) {
				final List<XmlChainItem> certChainTokens = new ArrayList<>();
				certChainTokens.add(getXmlChainItem(certificateByPubKey));
				List<XmlChainItem> certChain = getXmlForCertificateChain(certificateByPubKey);
				if (Utils.isCollectionNotEmpty(certChain)) {
					certChainTokens.addAll(certChain);
				}
				return certChainTokens;
			}
		}
		return null;
	}

	private List<XmlChainItem> getXmlForCertificateChain(final Token token) {
		if (token != null) {
			final List<XmlChainItem> certChainTokens = new ArrayList<>();
			Set<CertificateToken> processedTokens = new HashSet<>();
			CertificateToken issuerToken = getIssuerCertificate(token);
			while (issuerToken != null) {
				certChainTokens.add(getXmlChainItem(issuerToken));
				if (issuerToken.isSelfSigned() || processedTokens.contains(issuerToken)) {
					break;
				}
				processedTokens.add(issuerToken);
				issuerToken = getIssuerCertificate(issuerToken);
			}
			return certChainTokens;
		}
		return null;
	}

	private XmlChainItem getXmlChainItem(final CertificateToken token) {
		final XmlChainItem chainItem = new XmlChainItem();
		chainItem.setCertificate(xmlCertsMap.get(token.getDSSIdAsString()));
		return chainItem;
	}

	/**
	 * This method creates the SigningCertificate element for the current token.
	 *
	 * @param token
	 *              the token
	 * @return
	 */
	private XmlSigningCertificate getXmlSigningCertificate(final Token token) {
		final XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
		final CertificateToken certificateByPubKey = getIssuerCertificate(token);
		if (certificateByPubKey != null) {
			xmlSignCertType.setCertificate(xmlCertsMap.get(certificateByPubKey.getDSSIdAsString()));
			signingCertificateMap.put(token.getDSSIdAsString(), certificateByPubKey);
		} else if (token.getPublicKeyOfTheSigner() != null) {
			xmlSignCertType.setPublicKey(token.getPublicKeyOfTheSigner().getEncoded());
		} else {
			return null;
		}
		return xmlSignCertType;
	}

	private CertificateToken getIssuerCertificate(final Token token) {
		if (token != null && token.getPublicKeyOfTheSigner() != null) {
			if (token instanceof OCSPToken) {
				CertificateToken issuer = getIssuerForOCSPToken((OCSPToken) token);
				if (issuer != null) {
					return issuer;
				}
			}
			if (token instanceof TimestampToken) {
				CertificateToken issuer = getIssuerForTimestampToken((TimestampToken) token);
				if (issuer != null) {
					return issuer;
				}
			}
			List<CertificateToken> issuers = getCertsWithPublicKey(token.getPublicKeyOfTheSigner(), usedCertificates);
			if (Utils.isCollectionNotEmpty(issuers)) {
				for (CertificateToken cert : issuers) {
					if (cert.isValidOn(token.getCreationDate())) {
						return cert;
					}
				}
				return issuers.iterator().next();
			}
		}
		return null;
	}
	
	private CertificateToken getIssuerForOCSPToken(final OCSPToken token) {
		List<CertificateToken> issuers = getCertsWithPublicKey(token.getPublicKeyOfTheSigner(), token.getCertificateSource().getCertificates());
		if (Utils.isCollectionNotEmpty(issuers)) {
			for (CertificateToken cert : issuers) {
				if (cert.isValidOn(token.getCreationDate())) {
					return cert;
				}
			}
		}
		return null;
	}
	
	private CertificateToken getIssuerForTimestampToken(final TimestampToken token) {
		List<CertificateToken> issuers = getCertsWithPublicKey(token.getPublicKeyOfTheSigner(), token.getCertificateSource().getCertificates());
		if (Utils.isCollectionNotEmpty(issuers)) {
			for (CertificateToken cert : issuers) {
				if (cert.isValidOn(token.getCreationDate())) {
					return cert;
				}
			}
		}
		return null;
	}
	
	private CertificateToken getCertificateByPubKey(final PublicKey publicKey) {
		if (publicKey != null) {
			List<CertificateToken> issuers = getCertsWithPublicKey(publicKey, usedCertificates);
			if (Utils.isCollectionNotEmpty(issuers)) {
				return issuers.iterator().next();
			}
		}
		return null;
	}
	
	private List<CertificateToken> getCertsWithPublicKey(final PublicKey publicKey, final Collection<CertificateToken> candidates) {
		List<CertificateToken> founds = new ArrayList<>();
		
		if (publicKey != null) {			
			for (CertificateToken cert : candidates) {
				if (publicKey.equals(cert.getPublicKey())) {
					founds.add(cert);
					if (trustedCertSources.isTrusted(cert)) {
						return Arrays.asList(cert);
					}
				}
			}
		}
		return founds;
	}

	private CertificateToken getCertificateByCertificateIdentifier(final CertificateIdentifier certificateIdentifier) {
		if (certificateIdentifier == null) {
			return null;
		}

		List<CertificateToken> founds = new ArrayList<>();
		for (CertificateToken cert : usedCertificates) {
			if (certificateIdentifier.isRelatedToCertificate(cert)) {
				founds.add(cert);
				if (trustedCertSources.isTrusted(cert)) {
					return cert;
				}
			}
		}

		if (Utils.isCollectionNotEmpty(founds)) {
			return founds.iterator().next();
		}
		return null;
	}

	private XmlSigningCertificate getXmlSigningCertificate(Identifier tokenIdentifier, CertificateValidity certificateValidity) {
		XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
		CertificateToken signingCertificate = getSigningCertificate(certificateValidity);
		if (signingCertificate != null) {
			xmlSignCertType.setCertificate(xmlCertsMap.get(signingCertificate.getDSSIdAsString()));
			signingCertificateMap.put(tokenIdentifier.asXmlId(), signingCertificate);
		} else if (certificateValidity.getPublicKey() != null) {
			xmlSignCertType.setPublicKey(certificateValidity.getPublicKey().getEncoded());
		} else if (certificateValidity.getSignerInfo() != null) {
			// TODO: add info to xsd
		}
		return xmlSignCertType;
	}
	
	private CertificateToken getSigningCertificate(CertificateValidity certificateValidity) {
		CertificateToken signingCertificateToken = certificateValidity.getCertificateToken();
		if (signingCertificateToken != null) {
			return signingCertificateToken;
		} else if (certificateValidity.getPublicKey() != null) {
			return getCertificateByPubKey(certificateValidity.getPublicKey());
		} else if (certificateValidity.getSignerInfo() != null) {
			return getCertificateByCertificateIdentifier(certificateValidity.getSignerInfo());
		}
		return null;
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

	private List<XmlCommitmentTypeIndication> getXmlCommitmentTypeIndications(List<CommitmentTypeIndication> commitmentTypeIndications) {
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			List<XmlCommitmentTypeIndication> xmlCommitmentTypeIndications = new ArrayList<>();
			for (CommitmentTypeIndication commitmentTypeIndication : commitmentTypeIndications) {
				xmlCommitmentTypeIndications.add(getXmlCommitmentTypeIndication(commitmentTypeIndication));
			}
			return xmlCommitmentTypeIndications;
		}
		return Collections.emptyList();
	}
	
	private XmlCommitmentTypeIndication getXmlCommitmentTypeIndication(CommitmentTypeIndication commitmentTypeIndication) {
		XmlCommitmentTypeIndication xmlCommitmentTypeIndication = new XmlCommitmentTypeIndication();
		xmlCommitmentTypeIndication.setIdentifier(commitmentTypeIndication.getIdentifier());
		xmlCommitmentTypeIndication.setDescription(commitmentTypeIndication.getDescription());
		xmlCommitmentTypeIndication.setDocumentationReferences(commitmentTypeIndication.getDocumentReferences());
		return xmlCommitmentTypeIndication;
	}

	private XmlDistinguishedName getXmlDistinguishedName(final String x500PrincipalFormat, final String value) {
		final XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat(x500PrincipalFormat);
		xmlDistinguishedName.setValue(value);
		return xmlDistinguishedName;
	}
	
	private List<String> getCleanedUrls(List<String> urls) {
		List<String> cleanedUrls = new ArrayList<>();
		for (String url : urls) {
			cleanedUrls.add(DSSUtils.removeControlCharacters(url));
		}
		return cleanedUrls;
	}

	private XmlFoundCertificates getXmlFoundCertificates(Identifier tokenIdentifier, TokenCertificateSource certificateSource) {
		XmlFoundCertificates xmlFoundCertificates = new XmlFoundCertificates();
		if (CertificateSourceType.OCSP_RESPONSE.equals(certificateSource.getCertificateSourceType())) {
			xmlFoundCertificates.getRelatedCertificates().addAll(getXmlRelatedCertificates((OCSPCertificateSource)certificateSource));
		} else { // Signature and Timestamp sources
			xmlFoundCertificates.getRelatedCertificates().addAll(getXmlRelatedCertificates((SignatureCertificateSource)certificateSource));
		}
		xmlFoundCertificates.getRelatedCertificates().addAll(getXmlRelatedCertificateForOrphanReferences(certificateSource));
		CertificateToken signingCertificate = signingCertificateMap.get(tokenIdentifier.asXmlId());
		xmlFoundCertificates.getOrphanCertificates().addAll(getOrphanCertificates(certificateSource, signingCertificate));
		return xmlFoundCertificates;
	}
	
	private List<XmlRelatedCertificate> getXmlRelatedCertificates(SignatureCertificateSource certificateSource) {
		Map<String, XmlRelatedCertificate> relatedCertificatesMap = new HashMap<>();
		
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.KEY_INFO, 
				certificateSource.getKeyInfoCertificates(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.SIGNED_DATA, 
				certificateSource.getSignedDataCertificates(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.CERTIFICATE_VALUES, 
				certificateSource.getCertificateValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.ATTR_AUTORITIES_CERT_VALUES, 
				certificateSource.getAttrAuthoritiesCertValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.TIMESTAMP_VALIDATION_DATA, 
				certificateSource.getTimeStampValidationDataCertValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.DSS_DICTIONARY, 
				certificateSource.getDSSDictionaryCertValues(), certificateSource);
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.VRI_DICTIONARY, 
				certificateSource.getVRIDictionaryCertValues(), certificateSource);
		
		return new ArrayList<>(relatedCertificatesMap.values());
	}
	
	private List<XmlRelatedCertificate> getXmlRelatedCertificates(OCSPCertificateSource certificateSource) {
		Map<String, XmlRelatedCertificate> relatedCertificatesMap = new HashMap<>();
		
		populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.BASIC_OCSP_RESP, 
				certificateSource.getCertificates(), certificateSource);
		
		return new ArrayList<>(relatedCertificatesMap.values());
	}
	
	private void populateCertificateOriginMap(Map<String, XmlRelatedCertificate> relatedCertificatesMap, CertificateOrigin origin,
			List<CertificateToken> certificateTokens, TokenCertificateSource certificateSource) {
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
	
	private XmlRelatedCertificate getXmlRelatedCertificate(CertificateOrigin origin, CertificateToken cert, TokenCertificateSource certificateSource) {
		XmlRelatedCertificate xrc = new XmlRelatedCertificate();
		xrc.getOrigins().add(origin);
		xrc.setCertificate(xmlCertsMap.get(cert.getDSSIdAsString()));
		List<CertificateRef> referencesForCertificateToken = certificateSource.getReferencesForCertificateToken(cert);
		for (CertificateRef certificateRef : referencesForCertificateToken) {
			for (CertificateRefOrigin refOrigin : certificateSource.getCertificateRefOrigins(certificateRef)) {
				XmlCertificateRef xmlCertificateRef = getXmlCertificateRef(certificateRef, refOrigin);
				if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(refOrigin)) {
					verifyAgainstCertificateToken(xmlCertificateRef, certificateRef, cert);
				}
				xrc.getCertificateRefs().add(xmlCertificateRef);
			}
			referenceMap.put(certificateRef.getDSSIdAsString(), cert.getDSSIdAsString());
		}		
		return xrc;
	}
	
	private XmlCertificateRef getXmlCertificateRef(CertificateRef ref, CertificateRefOrigin origin) {
		XmlCertificateRef certificateRef = new XmlCertificateRef();
		CertificateIdentifier certificateIdentifier = ref.getCertificateIdentifier();
		if (certificateIdentifier != null) {
			certificateRef.setIssuerSerial(getXmlIssuerSerial(certificateIdentifier));
		}
		Digest refDigest = ref.getCertDigest();
		ResponderId responderId = ref.getResponderId();
		if (refDigest != null) {
			certificateRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(refDigest.getAlgorithm(), refDigest.getValue()));
		} else if (certificateIdentifier != null)  {
			certificateRef.setSerialInfo(getXmlSignerInfo(certificateIdentifier));
		} else if (responderId != null) {
			certificateRef.setSerialInfo(getXmlSignerInfo(responderId));
		}
		certificateRef.setOrigin(origin);
		return certificateRef;
	}
	
	private void verifyAgainstCertificateToken(XmlCertificateRef xmlCertificateRef, CertificateRef ref, CertificateToken signingCertificate) {		
		CertificateTokenRefMatcher tokenRefMatcher = new CertificateTokenRefMatcher();
		XmlDigestAlgoAndValue digestAlgoAndValue = xmlCertificateRef.getDigestAlgoAndValue();
		if (digestAlgoAndValue != null) {
			digestAlgoAndValue.setMatch(signingCertificate != null && tokenRefMatcher.matchByDigest(signingCertificate, ref));
		}
		XmlIssuerSerial issuerSerial = xmlCertificateRef.getIssuerSerial();
		if (issuerSerial != null) {
			issuerSerial.setMatch(signingCertificate != null && 
					tokenRefMatcher.matchByIssuerName(signingCertificate, ref) && tokenRefMatcher.matchBySerialNumber(signingCertificate, ref));
		}
	}
	
	private XmlIssuerSerial getXmlIssuerSerial(CertificateIdentifier certificateIdentifier) {
		XmlIssuerSerial xmlIssuerSerial = new XmlIssuerSerial();
		xmlIssuerSerial.setValue(certificateIdentifier.getIssuerSerialEncoded());
		return xmlIssuerSerial;
	}
	
	private List<XmlRelatedCertificate> getXmlRelatedCertificateForOrphanReferences(TokenCertificateSource certificateSource) {
		List<XmlRelatedCertificate> relatedCertificates = new ArrayList<>();
		for (CertificateRef certificateRef : certificateSource.getOrphanCertificateRefs()) {
			CertificateToken certificateToken = getUsedCertificateByCertificateRef(certificateRef);
			if (certificateToken != null) {
				relatedCertificates.add(getXmlRelatedCertificate(certificateSource, certificateToken, certificateRef));
			}
		}
		return relatedCertificates;
	}
	
	private CertificateToken getUsedCertificateByCertificateRef(CertificateRef certificateRef) {
		CertificateTokenRefMatcher matcher = new CertificateTokenRefMatcher();
		// TODO don't use usedCertificates
		for (CertificateToken certificateToken : usedCertificates) {
			if (matcher.match(certificateToken, certificateRef)) {
				return certificateToken;
			}
		}
		return null;
	}
	
	private XmlRelatedCertificate getXmlRelatedCertificate(TokenCertificateSource certificateSource, 
			CertificateToken cert, CertificateRef certificateRef) {
		XmlRelatedCertificate xrc = new XmlRelatedCertificate();
		xrc.setCertificate(xmlCertsMap.get(cert.getDSSIdAsString()));
		for (CertificateRefOrigin refOrigin : certificateSource.getCertificateRefOrigins(certificateRef)) {
			XmlCertificateRef xmlCertificateRef = getXmlCertificateRef(certificateRef, refOrigin);
			if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(refOrigin)) {
				verifyAgainstCertificateToken(xmlCertificateRef, certificateRef, cert);
			}
			xrc.getCertificateRefs().add(xmlCertificateRef);
		}
		referenceMap.put(certificateRef.getDSSIdAsString(), cert.getDSSIdAsString());
		return xrc;
	}
	
	private List<XmlOrphanCertificate> getOrphanCertificates(TokenCertificateSource certificateSource, CertificateToken signingCertificate) {
		List<XmlOrphanCertificate> orphanCertificates = new ArrayList<>();

		// Orphan Certificate References
		List<CertificateRef> orphanCertificateRefs = certificateSource.getOrphanCertificateRefs();
		for (CertificateRef orphanCertificateRef : orphanCertificateRefs) {
			// create orphan if certificate is not present
			if (getUsedCertificateByCertificateRef(orphanCertificateRef) == null) {
				orphanCertificates.add(createXmlOrphanCertificate(certificateSource, orphanCertificateRef, signingCertificate));
			}
		}
		
		return orphanCertificates;
	}
	
	private XmlOrphanCertificate createXmlOrphanCertificate(TokenCertificateSource certificateSource, CertificateRef orphanCertificateRef, 
			CertificateToken signingCertificate) {
		XmlOrphanCertificate orphanCertificate = new XmlOrphanCertificate();
		orphanCertificate.setToken(createXmlOrphanCertificateToken(orphanCertificateRef));
		for (CertificateRefOrigin refOrigin : certificateSource.getCertificateRefOrigins(orphanCertificateRef)) {
			XmlCertificateRef xmlCertificateRef = getXmlCertificateRef(orphanCertificateRef, refOrigin);
			if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(refOrigin)) {
				verifyAgainstCertificateToken(xmlCertificateRef, orphanCertificateRef, signingCertificate);
			}
			orphanCertificate.getCertificateRefs().add(xmlCertificateRef);
		}
		return orphanCertificate;
	}

	private XmlOrphanCertificateToken createXmlOrphanCertificateToken(CertificateRef orphanCertificateRef) {
		XmlOrphanCertificateToken orphanToken = new XmlOrphanCertificateToken();
		orphanToken.setId(orphanCertificateRef.getDSSIdAsString());
		if (orphanCertificateRef.getCertDigest() != null) {
			orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(orphanCertificateRef.getCertDigest()));
		}
		xmlOrphanCertificateTokensMap.put(orphanCertificateRef.getDSSIdAsString(), orphanToken);
		return orphanToken;
	}

	private List<XmlFoundTimestamp> getXmlFoundTimestamps(AdvancedSignature signature) {
		List<XmlFoundTimestamp> foundTimestamps = new ArrayList<>();
		for (TimestampToken timestampToken : signature.getAllTimestamps()) {
			XmlFoundTimestamp foundTimestamp = new XmlFoundTimestamp();
			foundTimestamp.setTimestamp(xmlTimestampsMap.get(timestampToken.getDSSIdAsString()));
			foundTimestamp.setLocation(timestampToken.getTimestampLocation());
			foundTimestamps.add(foundTimestamp);
		}
		return foundTimestamps;
	}
	
	private XmlFoundRevocations getXmlFoundRevocations(OfflineRevocationSource<CRL> crlSource, OfflineRevocationSource<OCSP> ocspSource) {
		XmlFoundRevocations foundRevocations = new XmlFoundRevocations();
		foundRevocations.getRelatedRevocations().addAll(getXmlRelatedRevocations(crlSource, ocspSource));
		foundRevocations.getOrphanRevocations().addAll(getXmlOrphanRevocations(crlSource, ocspSource));
		foundRevocations.getOrphanRevocations().addAll(getXmlOrphanRevocationRefs(crlSource, ocspSource));
		return foundRevocations;
	}
	
	private List<XmlRelatedRevocation> getXmlRelatedRevocations(OfflineRevocationSource<CRL> crlSource, OfflineRevocationSource<OCSP> ocspSource) {
		List<XmlRelatedRevocation> xmlRelatedRevocations = new ArrayList<>();
		addRelatedRevocations(xmlRelatedRevocations, crlSource);
		addRelatedRevocations(xmlRelatedRevocations, ocspSource);
		return xmlRelatedRevocations;
	}

	private <R extends Revocation> void addRelatedRevocations(List<XmlRelatedRevocation> result, OfflineRevocationSource<R> source) {
		for (Entry<RevocationToken<R>, Set<RevocationOrigin>> entry : source.getUniqueRevocationTokensWithOrigins().entrySet()) {
			RevocationToken<R> token = entry.getKey();
			String id = token.getDSSIdAsString();
			XmlRevocation xmlRevocation = xmlRevocationsMap.get(id);
			if (xmlRevocation != null) {
				XmlRelatedRevocation xmlRelatedRevocation = new XmlRelatedRevocation();
				xmlRelatedRevocation.setRevocation(xmlRevocation);
				xmlRelatedRevocation.setType(token.getRevocationType());
				xmlRelatedRevocation.getOrigins().addAll(entry.getValue());
				xmlRelatedRevocation.getRevocationRefs()
						.addAll(getXmlRevocationRefs(xmlRevocation.getId(), source.findRefsAndOriginsForRevocationToken(token)));
				result.add(xmlRelatedRevocation);
			}
		}
	}

	private List<XmlOrphanRevocation> getXmlOrphanRevocations(OfflineRevocationSource<CRL> crlSource, OfflineRevocationSource<OCSP> ocspSource) {
		List<XmlOrphanRevocation> xmlOrphanRevocations = new ArrayList<>();
		addOrphanRevocations(xmlOrphanRevocations, crlSource);
		addOrphanRevocations(xmlOrphanRevocations, ocspSource);
		return xmlOrphanRevocations;
	}

	private <R extends Revocation> void addOrphanRevocations(List<XmlOrphanRevocation> xmlOrphanRevocations, OfflineRevocationSource<R> source) {
		Map<EncapsulatedRevocationTokenIdentifier, Set<RevocationOrigin>> allBinariesWithOrigins = source.getAllRevocationBinariesWithOrigins();
		for (Entry<EncapsulatedRevocationTokenIdentifier, Set<RevocationOrigin>> entry : allBinariesWithOrigins.entrySet()) {
			EncapsulatedRevocationTokenIdentifier token = entry.getKey();
			String tokenId = token.asXmlId();
			if (!xmlRevocationsMap.containsKey(tokenId)) {
				XmlOrphanRevocation xmlOrphanRevocation = getXmlOrphanRevocation(token, entry.getValue());
				xmlOrphanRevocation.getRevocationRefs().addAll(getXmlRevocationRefs(tokenId, source.findRefsAndOriginsForBinary(token)));
				xmlOrphanRevocations.add(xmlOrphanRevocation);
			}
		}
	}

	private List<XmlOrphanRevocation> getXmlOrphanRevocationRefs(OfflineRevocationSource<CRL> crlSource, OfflineRevocationSource<OCSP> ocspSource) {
		List<XmlOrphanRevocation> xmlOrphanRevocationRefs = new ArrayList<>();
		addOrphanRevocationRefs(xmlOrphanRevocationRefs, crlSource, commonCRLSource);
		addOrphanRevocationRefs(xmlOrphanRevocationRefs, ocspSource, commonOCSPSource);
		return xmlOrphanRevocationRefs;
	}

	private <R extends Revocation> void addOrphanRevocationRefs(List<XmlOrphanRevocation> xmlOrphanRevocationRefs, OfflineRevocationSource<R> source, ListRevocationSource<R> allSources) {
		Map<RevocationRef<R>, Set<RevocationRefOrigin>> orphanRevocationReferencesWithOrigins = source.getOrphanRevocationReferencesWithOrigins();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : orphanRevocationReferencesWithOrigins.entrySet()) {
			RevocationRef<R> ref = entry.getKey();
			if (allSources.isOrphan(ref) && sourceDoesNotContainOrphanBinaries(source, ref)) {
				xmlOrphanRevocationRefs.add(createOrphanRevocationFromRef(ref, entry.getValue()));
			}
		}
	}
	
	private <R extends Revocation> boolean sourceDoesNotContainOrphanBinaries(OfflineRevocationSource<R> source, RevocationRef<R> ref) {
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

	private <R extends Revocation> List<XmlRevocationRef> getXmlRevocationRefs(String tokenId, Map<RevocationRef<R>, Set<RevocationRefOrigin>> refsAndOrigins) {
		List<XmlRevocationRef> xmlRevocationRefs = new ArrayList<>();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : refsAndOrigins.entrySet()) {
			RevocationRef<R> ref = entry.getKey();
			Set<RevocationRefOrigin> origins = entry.getValue();
			XmlRevocationRef xmlRef = null;
			if (ref instanceof CRLRef) {
				xmlRef = getXmlCRLRevocationRef((CRLRef) ref, origins);
			} else {
				xmlRef = getXmlOCSPRevocationRef((OCSPRef) ref, origins);
			}
			referenceMap.put(ref.getDSSIdAsString(), tokenId);
			xmlRevocationRefs.add(xmlRef);
		}
		return xmlRevocationRefs;
	}
	
	private XmlRevocationRef getXmlCRLRevocationRef(CRLRef crlRef, Set<RevocationRefOrigin> origins) {
		XmlRevocationRef xmlRevocationRef = new XmlRevocationRef();
		xmlRevocationRef.getOrigins().addAll(origins);
		if (crlRef.getDigest() != null) {
			xmlRevocationRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(crlRef.getDigest()));
		}
		return xmlRevocationRef;
	}
	
	private XmlRevocationRef getXmlOCSPRevocationRef(OCSPRef ocspRef, Set<RevocationRefOrigin> origins) {
		XmlRevocationRef xmlRevocationRef = new XmlRevocationRef();
		xmlRevocationRef.getOrigins().addAll(origins);
		if (ocspRef.getDigest() != null) {
			xmlRevocationRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(ocspRef.getDigest()));
		}
		xmlRevocationRef.setProducedAt(ocspRef.getProducedAt());
		ResponderId responderId = ocspRef.getResponderId();
		if (responderId != null) {
			xmlRevocationRef.setResponderId(getXmlSignerInfo(responderId));
		}
		return xmlRevocationRef;
	}
	
	private <R extends Revocation> XmlOrphanRevocation getXmlOrphanRevocation(EncapsulatedRevocationTokenIdentifier token, Set<RevocationOrigin> origins) {
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
	
	private XmlOrphanRevocationToken createOrphanTokenFromRevocationIdentifier(EncapsulatedRevocationTokenIdentifier revocationIdentifier) {
		XmlOrphanRevocationToken orphanToken = new XmlOrphanRevocationToken();
		String tokenId = revocationIdentifier.asXmlId();
		orphanToken.setId(tokenId);
		if (tokenExtractionStategy.isRevocationData()) {
			orphanToken.setBase64Encoded(revocationIdentifier.getBinaries());
		} else {
			byte[] digestValue = revocationIdentifier.getDigestValue(defaultDigestAlgorithm);
			orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, digestValue));
		}
		if (revocationIdentifier instanceof CRLBinary) {
			orphanToken.setType(RevocationType.CRL);
		} else {
			orphanToken.setType(RevocationType.OCSP);
		}
		xmlOrphanRevocationTokensMap.put(tokenId, orphanToken);
		return orphanToken;
	}
	
	private <R extends Revocation> XmlOrphanRevocation createOrphanRevocationFromRef(RevocationRef<R> ref, Set<RevocationRefOrigin> origins) {
		XmlOrphanRevocation xmlOrphanRevocation = new XmlOrphanRevocation();
		
		XmlOrphanRevocationToken orphanToken = new XmlOrphanRevocationToken();
		orphanToken.setId(ref.getDSSIdAsString());
		orphanToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(ref.getDigest()));
		xmlOrphanRevocationTokensMap.put(ref.getDSSIdAsString(), orphanToken);
		
		xmlOrphanRevocation.setToken(orphanToken);
		if (ref instanceof CRLRef) {
			orphanToken.setType(RevocationType.CRL);
			xmlOrphanRevocation.setType(RevocationType.CRL);
			xmlOrphanRevocation.getRevocationRefs().add(getXmlCRLRevocationRef((CRLRef) ref, origins));
		} else {
			orphanToken.setType(RevocationType.OCSP);
			xmlOrphanRevocation.setType(RevocationType.OCSP);
			xmlOrphanRevocation.getRevocationRefs().add(getXmlOCSPRevocationRef((OCSPRef) ref, origins));
		}
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

		xmlPolicy.setId(signaturePolicy.getIdentifier());
		xmlPolicy.setUrl(DSSUtils.removeControlCharacters(signaturePolicy.getUrl()));
		xmlPolicy.setDescription(signaturePolicy.getDescription());
		xmlPolicy.setDocumentationReferences(signaturePolicy.getDocumentationReferences());
		xmlPolicy.setNotice(signaturePolicy.getNotice());
		xmlPolicy.setZeroHash(signaturePolicy.isZeroHash());
		
		List<String> transformsDescription = signaturePolicy.getTransformsDescription();
		if (Utils.isCollectionNotEmpty(transformsDescription)) {
			xmlPolicy.setTransformations(transformsDescription);
		}

		final Digest digest = signaturePolicy.getDigest();
		if (digest != null) {
			xmlPolicy.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(digest));
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
			if (!signaturePolicy.isZeroHash()) {
				xmlPolicy.setDigestAlgorithmsEqual(validator.isDigestAlgorithmsEqual());
			}
			xmlPolicy.setIdentified(validator.isIdentified());
			xmlPolicy.setStatus(validator.isStatus());
			if (Utils.isStringNotBlank(validator.getProcessingErrors())) {
				xmlPolicy.setProcessingError(validator.getProcessingErrors());
			}
		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			xmlPolicy.setStatus(false);
			xmlPolicy.setProcessingError(e.getMessage());
			// Do nothing
			String errorMessage = "An error occurred during validation a signature policy with id '{}'. Reason : [{}]";
			if (LOG.isDebugEnabled()) {
				LOG.error(errorMessage, signaturePolicy.getIdentifier(), e.getMessage(), e);
			} else {
				LOG.error(errorMessage, signaturePolicy.getIdentifier(), e.getMessage());
			}
		}
		return xmlPolicy;
	}

	private XmlTimestamp buildDetachedXmlTimestamp(final TimestampToken timestampToken) {

		final XmlTimestamp xmlTimestampToken = new XmlTimestamp();

		xmlTimestampToken.setId(timestampToken.getDSSIdAsString());
		xmlTimestampToken.setType(timestampToken.getTimeStampType());
		xmlTimestampToken.setArchiveTimestampType(timestampToken.getArchiveTimestampType()); // property is defined only for archival timestamps
		xmlTimestampToken.setProductionTime(timestampToken.getGenerationTime());
		xmlTimestampToken.setTimestampFilename(timestampToken.getFileName());
		xmlTimestampToken.getDigestMatchers().addAll(getXmlDigestMatchers(timestampToken));
		xmlTimestampToken.setBasicSignature(getXmlBasicSignature(timestampToken));
		xmlTimestampToken.setSignerInformationStore(getXmlSignerInformationStore(timestampToken.getSignerInformationStoreInfos()));
		xmlTimestampToken.setPDFRevision(getXmlPDFRevision(timestampToken.getPdfRevision())); // used only for PAdES RFC 3161 timestamps

		final CandidatesForSigningCertificate candidatesForSigningCertificate = timestampToken.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {
			xmlTimestampToken.setSigningCertificate(getXmlSigningCertificate(timestampToken.getDSSId(), theCertificateValidity));
			xmlTimestampToken.setCertificateChain(getXmlForCertificateChain(theCertificateValidity.getPublicKey()));
		}
		
		xmlTimestampToken.setFoundCertificates(getXmlFoundCertificates(timestampToken.getDSSId(), timestampToken.getCertificateSource()));
		xmlTimestampToken.setFoundRevocations(getXmlFoundRevocations(timestampToken.getCRLSource(), timestampToken.getOCSPSource()));

		if (tokenExtractionStategy.isTimestamp()) {
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
				throw new DSSException("Unsupported category " + timestampReference.getCategory());
				
		}
		
		if (TimestampedObjectType.CERTIFICATE.equals(timestampedObj.getCategory())) {
			timestampedObj.setToken(xmlOrphanCertificateTokensMap.get(objectId));
			timestampedObj.setCategory(TimestampedObjectType.ORPHAN_CERTIFICATE);
			
		} else if (TimestampedObjectType.REVOCATION.equals(timestampedObj.getCategory())) {
			timestampedObj.setToken(xmlOrphanRevocationTokensMap.get(objectId));
			timestampedObj.setCategory(TimestampedObjectType.ORPHAN_REVOCATION);
			
		} else {
			throw new DSSException(String.format("The type of object [%s] is not supported for Orphan Tokens!", timestampedObj.getCategory()));
			
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

	private XmlBasicSignature getXmlBasicSignature(final Token token) {
		final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();

		SignatureAlgorithm signatureAlgorithm = token.getSignatureAlgorithm();
		if (signatureAlgorithm != null) {
			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm());
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm());
			xmlBasicSignatureType.setMaskGenerationFunctionUsedToSignThisToken(signatureAlgorithm.getMaskGenerationFunction());
		}
		xmlBasicSignatureType.setKeyLengthUsedToSignThisToken(DSSPKUtils.getPublicKeySize(token));

		SignatureValidity signatureValidity = token.getSignatureValidity();
		if (SignatureValidity.NOT_EVALUATED != signatureValidity) {
			final boolean signatureValid = SignatureValidity.VALID == token.getSignatureValidity();
			xmlBasicSignatureType.setSignatureIntact(signatureValid);
			xmlBasicSignatureType.setSignatureValid(signatureValid);
		}
		return xmlBasicSignatureType;
	}

	private XmlBasicSignature getXmlBasicSignature(AdvancedSignature signature, PublicKey signingCertificatePublicKey) {
		XmlBasicSignature xmlBasicSignature = new XmlBasicSignature();
		xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(signature.getEncryptionAlgorithm());

		final int keyLength = signingCertificatePublicKey == null ? 0 : DSSPKUtils.getPublicKeySize(signingCertificatePublicKey);
		xmlBasicSignature.setKeyLengthUsedToSignThisToken(String.valueOf(keyLength));
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
				if (Utils.isCollectionNotEmpty(dependentValidations) && 
						(Utils.isCollectionNotEmpty(signature.getDetachedContents()) || isAtLeastOneFound(dependentValidations))) {
					for (ReferenceValidation dependentValidation : referenceValidation.getDependentValidations()) {
						refs.add(getXmlDigestMatcher(dependentValidation));
					}
				}
			}
		}
		return refs;
	}
	
	/**
	 * Checks if at least one Manifest entry was found
	 * @return TRUE if at least one ManifestEntry was found, FALSE otherwise
	 */
	public boolean isAtLeastOneFound(List<ReferenceValidation> referenceValidations) {
		for (ReferenceValidation referenceValidation : referenceValidations) {
			if (referenceValidation.isFound()) {
				return true;
			}
		}
		return false;
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
		return ref;
	}

	private List<XmlSignatureScope> getXmlSignatureScopes(List<SignatureScope> scopes) {
		List<XmlSignatureScope> xmlScopes = new ArrayList<>();
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
		xmlSignatureScope.setSignerData(xmlSignedDataMap.get(scope.getDSSIdAsString()));
		return xmlSignatureScope;
	}

	private XmlCertificate buildDetachedXmlCertificate(CertificateToken certToken) {

		final XmlCertificate xmlCert = new XmlCertificate();

		xmlCert.setId(certToken.getDSSIdAsString());

		X500PrincipalHelper subject = certToken.getSubject();
		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.CANONICAL, subject.getCanonical()));
		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, subject.getRFC2253()));

		X500PrincipalHelper issuer = certToken.getIssuer();
		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.CANONICAL, issuer.getCanonical()));
		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, issuer.getRFC2253()));

		xmlCert.setSerialNumber(certToken.getSerialNumber());

		xmlCert.setSubjectSerialNumber(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.SERIALNUMBER, subject));
		xmlCert.setCommonName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, subject));
		xmlCert.setLocality(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.L, subject));
		xmlCert.setState(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.ST, subject));
		xmlCert.setCountryName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, subject));
		xmlCert.setOrganizationIdentifier(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.ORGANIZATION_IDENTIFIER, subject));
		xmlCert.setOrganizationName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, subject));
		xmlCert.setOrganizationalUnit(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.OU, subject));
		xmlCert.setGivenName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.GIVENNAME, subject));
		xmlCert.setSurname(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.SURNAME, subject));
		xmlCert.setPseudonym(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.PSEUDONYM, subject));
		xmlCert.setEmail(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.E, subject));

		List<String> subjectAlternativeNames = DSSASN1Utils.getSubjectAlternativeNames(certToken);
		if (Utils.isCollectionNotEmpty(subjectAlternativeNames)) {
			xmlCert.setSubjectAlternativeNames(subjectAlternativeNames);
		}

		xmlCert.setAuthorityInformationAccessUrls(getCleanedUrls(DSSASN1Utils.getCAAccessLocations(certToken)));
		xmlCert.setOCSPAccessUrls(getCleanedUrls(DSSASN1Utils.getOCSPAccessLocations(certToken)));
		xmlCert.setCRLDistributionPoints(getCleanedUrls(DSSASN1Utils.getCrlUrls(certToken)));
		
		xmlCert.setSources(getXmlCertificateSources(certToken));

		xmlCert.setNotAfter(certToken.getNotAfter());
		xmlCert.setNotBefore(certToken.getNotBefore());
		final PublicKey publicKey = certToken.getPublicKey();
		xmlCert.setPublicKeySize(DSSPKUtils.getPublicKeySize(publicKey));
		xmlCert.setPublicKeyEncryptionAlgo(EncryptionAlgorithm.forKey(publicKey));
		xmlCert.setEntityKey(certToken.getEntityKey().asXmlId());

		xmlCert.setKeyUsageBits(certToken.getKeyUsageBits());
		xmlCert.setExtendedKeyUsages(getXmlOids(DSSASN1Utils.getExtendedKeyUsage(certToken)));

		xmlCert.setIdPkixOcspNoCheck(DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken));

		xmlCert.setPSD2Info(getPSD2Info(certToken));

		xmlCert.setBasicSignature(getXmlBasicSignature(certToken));

		xmlCert.setQCStatementIds(getXmlOids(DSSASN1Utils.getQCStatementsIdList(certToken)));
		xmlCert.setQCTypes(getXmlOids(DSSASN1Utils.getQCTypesIdList(certToken)));
		xmlCert.setCertificatePolicies(getXmlCertificatePolicies(DSSASN1Utils.getCertificatePolicies(certToken)));
		xmlCert.setSemanticsIdentifier(getXmlOid(DSSASN1Utils.getSemanticsIdentifier(certToken)));

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(trustedCertSources.isTrusted(certToken));

		if (tokenExtractionStategy.isCertificate()) {
			xmlCert.setBase64Encoded(certToken.getEncoded());
		} else {
			byte[] certDigest = certToken.getDigest(defaultDigestAlgorithm);
			xmlCert.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, certDigest));
		}

		return xmlCert;
	}

	private XmlOID getXmlOid(OidDescription oidDescription) {
		if (oidDescription == null) {
			return null;
		}
		XmlOID xmlOID = new XmlOID();
		xmlOID.setValue(oidDescription.getOid());
		xmlOID.setDescription(oidDescription.getDescription());
		return xmlOID;
	}

	private XmlPSD2Info getPSD2Info(CertificateToken certToken) {
		PSD2QcType psd2QcStatement = DSSASN1Utils.getPSD2QcStatement(certToken);
		if (psd2QcStatement != null) {
			XmlPSD2Info xmlInfo = new XmlPSD2Info();
			xmlInfo.setNcaId(psd2QcStatement.getNcaId());
			xmlInfo.setNcaName(psd2QcStatement.getNcaName());
			List<RoleOfPSP> rolesOfPSP = psd2QcStatement.getRolesOfPSP();
			List<XmlPSD2Role> psd2Roles = new ArrayList<>();
			for (RoleOfPSP roleOfPSP : rolesOfPSP) {
				XmlPSD2Role xmlRole = new XmlPSD2Role();
				RoleOfPspOid role = roleOfPSP.getPspOid();
				xmlRole.setPspOid(getXmlOid(role));
				xmlRole.setPspName(roleOfPSP.getPspName());
				psd2Roles.add(xmlRole);
			}
			xmlInfo.setPSD2Roles(psd2Roles);
			return xmlInfo;
		}
		return null;
	}

	private List<CertificateSourceType> getXmlCertificateSources(final CertificateToken token) {
		List<CertificateSourceType> certificateSources = new ArrayList<>();
		if (certificateSourceTypes != null) {
			Set<CertificateSourceType> sourceTypes = certificateSourceTypes.get(token);
			if (sourceTypes != null) {
				certificateSources.addAll(sourceTypes);
			}
		}
		if (Utils.isCollectionEmpty(certificateSources)) {
			certificateSources.add(CertificateSourceType.UNKNOWN);
		}
		return certificateSources;
	}

	private Set<RevocationToken<Revocation>> getRevocationsForCert(CertificateToken certToken) {
		Set<RevocationToken<Revocation>> revocations = new HashSet<>();
		if (Utils.isCollectionNotEmpty(usedRevocations)) {
			for (RevocationToken<Revocation> revocationToken : usedRevocations) {
				if (Utils.areStringsEqual(certToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())) {
					revocations.add(revocationToken);
				}
			}
		}
		return revocations;
	}

	private List<XmlCertificatePolicy> getXmlCertificatePolicies(List<CertificatePolicy> certificatePolicies) {
		List<XmlCertificatePolicy> result = new ArrayList<>();
		for (CertificatePolicy cp : certificatePolicies) {
			XmlCertificatePolicy xmlCP = new XmlCertificatePolicy();
			xmlCP.setValue(cp.getOid());
			xmlCP.setDescription(OidRepository.getDescription(cp.getOid()));
			xmlCP.setCpsUrl(DSSUtils.removeControlCharacters(cp.getCpsUrl()));
			result.add(xmlCP);
		}
		return result;
	}

	private List<XmlOID> getXmlOids(List<String> oidList) {
		List<XmlOID> result = new ArrayList<>();
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
		List<XmlTrustedServiceProvider> result = new ArrayList<>();
		Map<CertificateToken, List<TrustProperties>> servicesByTrustedCert = getRelatedTrustServices(certToken);
		for (Entry<CertificateToken, List<TrustProperties>> entry : servicesByTrustedCert.entrySet()) {
			CertificateToken trustedCert = entry.getKey();
			List<TrustProperties> services = entry.getValue();

			Map<TrustServiceProvider, List<TrustProperties>> servicesByProviders = classifyByServiceProvider(
					services);

			for (Entry<TrustServiceProvider, List<TrustProperties>> servicesByProvider : servicesByProviders
					.entrySet()) {

				List<TrustProperties> trustServices = servicesByProvider.getValue();
				XmlTrustedServiceProvider serviceProvider = buildXmlTrustedServiceProvider(trustServices.iterator().next());
				serviceProvider.setTrustedServices(buildXmlTrustedServices(trustServices, certToken, trustedCert));
				result.add(serviceProvider);
			}

		}
		return Collections.unmodifiableList(result);
	}

	private XmlTrustedServiceProvider buildXmlTrustedServiceProvider(TrustProperties trustProperties) {
		XmlTrustedServiceProvider result = new XmlTrustedServiceProvider();
		if (trustProperties.getLOTLIdentifier() != null) {
			result.setLOTL(xmlTrustedListsMap.get(trustProperties.getLOTLIdentifier().asXmlId()));
		}
		if (trustProperties.getTLIdentifier() != null) {
			result.setTL(xmlTrustedListsMap.get(trustProperties.getTLIdentifier().asXmlId()));
		}
		TrustServiceProvider tsp = trustProperties.getTrustServiceProvider();
		result.setTSPNames(getLangAndValues(tsp.getNames()));
		result.setTSPTradeNames(getLangAndValues(tsp.getTradeNames()));
		result.setTSPRegistrationIdentifiers(tsp.getRegistrationIdentifiers());
		return result;
	}

	private List<XmlLangAndValue> getLangAndValues(Map<String, List<String>> map) {
		if (Utils.isMapNotEmpty(map)) {
			List<XmlLangAndValue> result = new ArrayList<>();
			for (Entry<String, List<String>> entry : map.entrySet()) {
				String lang = entry.getKey();
				for (String value : entry.getValue()) {
					XmlLangAndValue langAndValue = new XmlLangAndValue();
					langAndValue.setLang(lang);
					langAndValue.setValue(value);
					result.add(langAndValue);
				}
			}
			return result;
		}
		return null;
	}

	private Map<CertificateToken, List<TrustProperties>> getRelatedTrustServices(CertificateToken certToken) {
		Map<CertificateToken, List<TrustProperties>> result = new HashMap<>();
		Set<CertificateToken> processedTokens = new HashSet<>();
		for (CertificateSource trustedSource : trustedCertSources.getSources()) {
			if (trustedSource instanceof TrustedListsCertificateSource) {
				TrustedListsCertificateSource trustedCertSource = (TrustedListsCertificateSource) trustedSource;
				while (certToken != null) {
					List<TrustProperties> trustServices = trustedCertSource.getTrustServices(certToken);
					if (!trustServices.isEmpty()) {
						result.put(certToken, trustServices);
					}
					if (certToken.isSelfSigned() || processedTokens.contains(certToken)) {
						break;
					}
					processedTokens.add(certToken);
					certToken = getIssuerCertificate(certToken);
				}
			}
		}
		return result;
	}

	private List<XmlTrustedService> buildXmlTrustedServices(List<TrustProperties> trustPropertiesList,
			CertificateToken certToken, CertificateToken trustedCert) {
		List<XmlTrustedService> result = new ArrayList<>();

		for (TrustProperties trustProperties : trustPropertiesList) {
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService = trustProperties.getTrustService();
			List<TrustServiceStatusAndInformationExtensions> serviceStatusAfterOfEqualsCertIssuance = trustService.getAfter(certToken.getNotBefore());
			if (Utils.isCollectionNotEmpty(serviceStatusAfterOfEqualsCertIssuance)) {
				for (TrustServiceStatusAndInformationExtensions serviceInfoStatus : serviceStatusAfterOfEqualsCertIssuance) {
					XmlTrustedService trustedService = new XmlTrustedService();

					trustedService.setServiceDigitalIdentifier(xmlCertsMap.get(trustedCert.getDSSIdAsString()));
					trustedService.setServiceNames(getLangAndValues(serviceInfoStatus.getNames()));
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

	private Map<TrustServiceProvider, List<TrustProperties>> classifyByServiceProvider(
			List<TrustProperties> trustPropertiesList) {
		Map<TrustServiceProvider, List<TrustProperties>> servicesByProviders = new HashMap<>();
		if (Utils.isCollectionNotEmpty(trustPropertiesList)) {
			for (TrustProperties trustProperties : trustPropertiesList) {
				TrustServiceProvider currentTrustServiceProvider = trustProperties.getTrustServiceProvider();
				List<TrustProperties> list = servicesByProviders.get(currentTrustServiceProvider);
				if (list == null) {
					list = new ArrayList<>();
					servicesByProviders.put(currentTrustServiceProvider, list);
				}
				list.add(trustProperties);
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
	private List<String> getQualifiers(TrustServiceStatusAndInformationExtensions serviceInfoStatus, CertificateToken certificateToken) {
		LOG.trace("--> GET_QUALIFIERS()");
		List<String> list = new ArrayList<>();
		final List<ConditionForQualifiers> conditionsForQualifiers = serviceInfoStatus.getConditionsForQualifiers();
		if (Utils.isCollectionNotEmpty(conditionsForQualifiers)) {
			for (ConditionForQualifiers conditionForQualifiers : conditionsForQualifiers) {
				Condition condition = conditionForQualifiers.getCondition();
				if (condition.check(certificateToken)) {
					list.addAll(conditionForQualifiers.getQualifiers());
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
		xmlDigestAlgAndValue.setDigestMethod(digestAlgo);
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
