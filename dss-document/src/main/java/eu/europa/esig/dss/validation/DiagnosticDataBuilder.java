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

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIssuerSerial;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Info;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPSD2Role;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQCLimitValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.QCLimitValue;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.TokenComparator;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
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
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.PSD2QcType;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.RoleOfPSP;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Contains a common code for DiagnosticData building
 *
 */
public abstract class DiagnosticDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(DiagnosticDataBuilder.class);

	/** The certificates used during the validation process */
	protected Set<CertificateToken> usedCertificates;

	/** The revocation used during the validation process */
	protected Set<RevocationToken<Revocation>> usedRevocations;

	/** The list of trusted certificate sources */
	protected ListCertificateSource trustedCertSources = new ListCertificateSource();

	/** The validation time */
	protected Date validationDate;

	/** A map between certificate tokens and source types where they been obtained from */
	protected Map<CertificateToken, Set<CertificateSourceType>> certificateSourceTypes;

	/** The token extraction strategy */
	protected TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/** The digest algorithm to use for digest computation */
	protected DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	/** The cached map of certificates */
	protected Map<String, XmlCertificate> xmlCertsMap = new HashMap<>();

	/** The cached map of revocation data */
	protected Map<String, XmlRevocation> xmlRevocationsMap = new HashMap<>();

	/** The cached map of trusted lists */
	protected Map<String, XmlTrustedList> xmlTrustedListsMap = new HashMap<>();

	/** The cached map of orphan certificates */
	protected Map<String, XmlOrphanCertificateToken> xmlOrphanCertificateTokensMap = new HashMap<>();

	/** The cached map of orphan revocation data */
	protected Map<String, XmlOrphanRevocationToken> xmlOrphanRevocationTokensMap = new HashMap<>();

	/**
	 * A map between references ids and their related token ids (used to map
	 * references for timestamped refs)
	 */
	protected Map<String, String> referenceMap = new HashMap<>();

	/**
	 * A map between certificate id Strings and the related CertificateTokens
	 */
	protected Map<String, CertificateToken> certificateIdsMap = new HashMap<>();

	/**
	 * A map between certificate id Strings and the related CertificateTokens for signing certificates
	 */
	protected Map<String, CertificateToken> signingCertificateMap = new HashMap<>();

	/**
	 * This method allows to set the used certificates
	 *
	 * @param usedCertificates the used certificates
	 * @return the builder
	 */
	public DiagnosticDataBuilder usedCertificates(Set<CertificateToken> usedCertificates) {
		this.usedCertificates = usedCertificates;
		return this;
	}

	/**
	 * This method allows to set the certificate source types
	 *
	 * @param certificateSourceTypes the certificate source types
	 * @return the builder
	 */
	public DiagnosticDataBuilder certificateSourceTypes(
			Map<CertificateToken, Set<CertificateSourceType>> certificateSourceTypes) {
		this.certificateSourceTypes = certificateSourceTypes;
		return this;
	}

	/**
	 * This method allows to set the used revocation data
	 *
	 * @param usedRevocations the used revocation data
	 * @return the builder
	 */
	public DiagnosticDataBuilder usedRevocations(Set<RevocationToken<Revocation>> usedRevocations) {
		this.usedRevocations = usedRevocations;
		return this;
	}

	/**
	 * This method allows to set the TrustedListsCertificateSources
	 *
	 * @param trustedCertSources the list of trusted lists certificate sources
	 * @return the builder
	 */
	public DiagnosticDataBuilder trustedCertificateSources(ListCertificateSource trustedCertSources) {
		if (trustedCertSources.areAllCertSourcesTrusted()) {
			this.trustedCertSources = trustedCertSources;
		} else {
			throw new DSSException(
					"Trusted CertificateSource must contain only sources of type TRUSTED_STORE or TRUSTED_LIST!");
		}
		return this;
	}

	/**
	 * This method allows to set the validation date
	 *
	 * @param validationDate the validation date
	 * @return the builder
	 */
	public DiagnosticDataBuilder validationDate(Date validationDate) {
		this.validationDate = validationDate;
		return this;
	}

	/**
	 * This method allows to set the {@link TokenExtractionStrategy} to follow for
	 * the token extraction
	 *
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy} to use
	 * @return the builder
	 */
	public DiagnosticDataBuilder tokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		this.tokenExtractionStrategy = tokenExtractionStrategy;
		return this;
	}

	/**
	 * This method allows to set the default {@link DigestAlgorithm} which will be
	 * used for tokens' DigestAlgoAndValue calculation
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to set as default
	 * @return the builder
	 */
	public DiagnosticDataBuilder defaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.defaultDigestAlgorithm = digestAlgorithm;
		return this;
	}

	/**
	 * Builds {@code XmlDiagnosticData}
	 *
	 * @return {@link XmlDiagnosticData}
	 */
	public XmlDiagnosticData build() {
		XmlDiagnosticData diagnosticData = new XmlDiagnosticData();
		diagnosticData.setValidationDate(validationDate);

		Collection<XmlCertificate> xmlCertificates = buildXmlCertificates(usedCertificates);
		diagnosticData.getUsedCertificates().addAll(xmlCertificates);
		linkSigningCertificateAndChains(usedCertificates);

		Collection<XmlRevocation> xmlRevocations = buildXmlRevocations(usedRevocations);
		diagnosticData.getUsedRevocations().addAll(xmlRevocations);

		linkCertificatesAndRevocations(usedCertificates);

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
				certificateToken = getProcessedCertificateToken(certificateToken); // ensure the token is processed
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
					LOG.warn(
							"The TrustedListsCertificateSource does not contain TLValidationJobSummary. TLValidationJob is not performed!");
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

	protected XmlSignerInfo getXmlSignerInfo(CertificateIdentifier certificateIdentifier) {
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

	protected XmlRevocation buildDetachedXmlRevocation(RevocationToken<Revocation> revocationToken) {

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
			xmlRevocation.setFoundCertificates(
					getXmlFoundCertificates(revocationToken.getDSSId(), revocationToken.getCertificateSource()));
		}

		if (tokenExtractionStrategy.isRevocationData()) {
			xmlRevocation.setBase64Encoded(revocationToken.getEncoded());
		} else {
			byte[] revocationDigest = revocationToken.getDigest(defaultDigestAlgorithm);
			xmlRevocation.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, revocationDigest));
		}

		return xmlRevocation;
	}

	protected <R extends Revocation> List<XmlRevocationRef> getXmlRevocationRefs(String tokenId,
																				 Map<RevocationRef<R>, Set<RevocationRefOrigin>> refsAndOrigins) {
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

	protected XmlRevocationRef getXmlCRLRevocationRef(CRLRef crlRef, Set<RevocationRefOrigin> origins) {
		XmlRevocationRef xmlRevocationRef = new XmlRevocationRef();
		xmlRevocationRef.getOrigins().addAll(origins);
		if (crlRef.getDigest() != null) {
			xmlRevocationRef.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(crlRef.getDigest()));
		}
		return xmlRevocationRef;
	}

	protected XmlRevocationRef getXmlOCSPRevocationRef(OCSPRef ocspRef, Set<RevocationRefOrigin> origins) {
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

	protected List<XmlChainItem> getXmlForCertificateChain(final Token token) {
		if (token != null) {
			final List<XmlChainItem> certChainTokens = new ArrayList<>();

			Set<Token> processedTokens = new HashSet<>();
			processedTokens.add(token);

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

	protected List<XmlChainItem> getXmlForCertificateChain(final PublicKey publicKey) {
		if (publicKey != null) {
			CertificateToken certificateByPubKey = getCertificateByPubKey(publicKey);
			if (certificateByPubKey != null) {
				final List<XmlChainItem> certChainTokens = new ArrayList<>();
				certChainTokens.add(getXmlChainItem(certificateByPubKey));
				List<XmlChainItem> certChain = getXmlForCertificateChain(certificateByPubKey);
				if (Utils.isCollectionNotEmpty(certChain)) {
					for (XmlChainItem chainItem : certChain) {
						if (certificateByPubKey.getDSSIdAsString().equals(chainItem.getCertificate().getId())) {
							break;
						}
						certChainTokens.add(chainItem);
					}
				}
				return certChainTokens;
			}
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
	 * @param token the token
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

			CertificateToken issuer = null;
			if (token instanceof OCSPToken) {
				issuer = getIssuerForOCSPToken((OCSPToken) token);
			}
			if (token instanceof TimestampToken) {
				issuer = getIssuerForTimestampToken((TimestampToken) token);
			}

			if (issuer != null) {
				return issuer;

			} else {
				List<CertificateToken> issuers = getCertsWithPublicKey(token.getPublicKeyOfTheSigner(),
						usedCertificates);
				if (Utils.isCollectionNotEmpty(issuers)) {
					for (CertificateToken cert : issuers) {
						if (cert.isValidOn(token.getCreationDate())) {
							return cert;
						}
					}
					return issuers.iterator().next();
				}
			}

		}
		return null;
	}

	private CertificateToken getIssuerForOCSPToken(final OCSPToken token) {
		List<CertificateToken> issuers = getCertsWithPublicKey(token.getPublicKeyOfTheSigner(),
				token.getCertificateSource().getCertificates());
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
		List<CertificateToken> issuers = getCertsWithPublicKey(token.getPublicKeyOfTheSigner(),
				token.getCertificateSource().getCertificates());
		if (Utils.isCollectionNotEmpty(issuers)) {
			for (CertificateToken cert : issuers) {
				if (cert.isValidOn(token.getCreationDate())) {
					return cert;
				}
			}
		}
		return null;
	}

	private List<CertificateToken> getCertsWithPublicKey(final PublicKey publicKey,
														 final Collection<CertificateToken> candidates) {
		List<CertificateToken> founds = new ArrayList<>();

		if (publicKey != null) {
			for (CertificateToken cert : candidates) {
				cert = getProcessedCertificateToken(cert);
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

	private CertificateToken getProcessedCertificateToken(CertificateToken certificateToken) {
		CertificateToken processedCertificateToken = certificateIdsMap.get(certificateToken.getDSSIdAsString());
		if (processedCertificateToken == null) {
			processedCertificateToken = certificateToken;
			certificateIdsMap.put(certificateToken.getDSSIdAsString(), certificateToken);
		}
		return processedCertificateToken;
	}

	protected XmlSigningCertificate getXmlSigningCertificate(Identifier tokenIdentifier,
															 CertificateValidity certificateValidity) {
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

	private CertificateToken getCertificateByPubKey(final PublicKey publicKey) {
		if (publicKey != null) {
			List<CertificateToken> issuers = getCertsWithPublicKey(publicKey, usedCertificates);
			if (Utils.isCollectionNotEmpty(issuers)) {
				return issuers.iterator().next();
			}
		}
		return null;
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

	protected XmlFoundCertificates getXmlFoundCertificates(Identifier tokenIdentifier,
														   TokenCertificateSource certificateSource) {
		XmlFoundCertificates xmlFoundCertificates = new XmlFoundCertificates();
		xmlFoundCertificates.getRelatedCertificates()
				.addAll(getXmlRelatedCertificates(certificateSource));
		xmlFoundCertificates.getRelatedCertificates()
				.addAll(getXmlRelatedCertificateForOrphanReferences(certificateSource));
		CertificateToken signingCertificate = signingCertificateMap.get(tokenIdentifier.asXmlId());
		xmlFoundCertificates.getOrphanCertificates()
				.addAll(getOrphanCertificates(certificateSource, signingCertificate));
		return xmlFoundCertificates;
	}

	private List<XmlRelatedCertificate> getXmlRelatedCertificates(TokenCertificateSource certificateSource) {
		Map<String, XmlRelatedCertificate> relatedCertificatesMap = new HashMap<>();

		if (CertificateSourceType.OCSP_RESPONSE.equals(certificateSource.getCertificateSourceType())) {
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.BASIC_OCSP_RESP,
					certificateSource.getCertificates(), certificateSource);

		} else {
			SignatureCertificateSource signatureCertificateSource = (SignatureCertificateSource) certificateSource;

			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.KEY_INFO,
					signatureCertificateSource.getKeyInfoCertificates(), certificateSource);
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.SIGNED_DATA,
					signatureCertificateSource.getSignedDataCertificates(), certificateSource);
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.CERTIFICATE_VALUES,
					signatureCertificateSource.getCertificateValues(), certificateSource);
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES,
					signatureCertificateSource.getAttrAuthoritiesCertValues(), certificateSource);
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.TIMESTAMP_VALIDATION_DATA,
					signatureCertificateSource.getTimeStampValidationDataCertValues(), certificateSource);
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.DSS_DICTIONARY,
					signatureCertificateSource.getDSSDictionaryCertValues(), certificateSource);
			populateCertificateOriginMap(relatedCertificatesMap, CertificateOrigin.VRI_DICTIONARY,
					signatureCertificateSource.getVRIDictionaryCertValues(), certificateSource);
		}

		return new ArrayList<>(relatedCertificatesMap.values());
	}

	protected void populateCertificateOriginMap(Map<String, XmlRelatedCertificate> relatedCertificatesMap,
												CertificateOrigin origin, List<CertificateToken> certificateTokens,
												TokenCertificateSource certificateSource) {
		for (CertificateToken certificateToken : certificateTokens) {
			if (!relatedCertificatesMap.containsKey(certificateToken.getDSSIdAsString())) {
				XmlRelatedCertificate xmlFoundCertificate = getXmlRelatedCertificate(origin, certificateToken,
						certificateSource);
				relatedCertificatesMap.put(certificateToken.getDSSIdAsString(), xmlFoundCertificate);
			} else {
				XmlRelatedCertificate storedFoundCertificate = relatedCertificatesMap
						.get(certificateToken.getDSSIdAsString());
				if (!storedFoundCertificate.getOrigins().contains(origin)) {
					storedFoundCertificate.getOrigins().add(origin);
				}
			}
		}
	}

	protected XmlRelatedCertificate getXmlRelatedCertificate(CertificateOrigin origin, CertificateToken cert,
															 TokenCertificateSource certificateSource) {
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

	protected XmlRelatedCertificate getXmlRelatedCertificate(TokenCertificateSource certificateSource,
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

	protected XmlCertificateRef getXmlCertificateRef(CertificateRef ref, CertificateRefOrigin origin) {
		XmlCertificateRef certificateRef = new XmlCertificateRef();
		CertificateIdentifier certificateIdentifier = ref.getCertificateIdentifier();
		if (certificateIdentifier != null) {
			certificateRef.setIssuerSerial(getXmlIssuerSerial(certificateIdentifier));
		}
		Digest refDigest = ref.getCertDigest();
		ResponderId responderId = ref.getResponderId();
		if (refDigest != null) {
			certificateRef
					.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(refDigest.getAlgorithm(), refDigest.getValue()));
		} else if (certificateIdentifier != null) {
			certificateRef.setSerialInfo(getXmlSignerInfo(certificateIdentifier));
		} else if (responderId != null) {
			certificateRef.setSerialInfo(getXmlSignerInfo(responderId));
		}
		certificateRef.setOrigin(origin);
		return certificateRef;
	}

	private List<XmlOrphanCertificate> getOrphanCertificates(TokenCertificateSource certificateSource,
															 CertificateToken signingCertificate) {
		List<XmlOrphanCertificate> orphanCertificates = new ArrayList<>();

		// Orphan Certificate References
		List<CertificateRef> orphanCertificateRefs = certificateSource.getOrphanCertificateRefs();
		for (CertificateRef orphanCertificateRef : orphanCertificateRefs) {
			// create orphan if certificate is not present
			if (getUsedCertificateByCertificateRef(orphanCertificateRef) == null) {
				orphanCertificates
						.add(createXmlOrphanCertificate(certificateSource, orphanCertificateRef, signingCertificate));
			}
		}

		return orphanCertificates;
	}

	private XmlOrphanCertificate createXmlOrphanCertificate(TokenCertificateSource certificateSource,
															CertificateRef orphanCertificateRef, CertificateToken signingCertificate) {
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

	protected List<XmlRelatedCertificate> getXmlRelatedCertificateForOrphanReferences(
			TokenCertificateSource certificateSource) {
		List<XmlRelatedCertificate> relatedCertificates = new ArrayList<>();
		for (CertificateRef certificateRef : certificateSource.getOrphanCertificateRefs()) {
			CertificateToken certificateToken = getUsedCertificateByCertificateRef(certificateRef);
			if (certificateToken != null) {
				relatedCertificates.add(getXmlRelatedCertificate(certificateSource, certificateToken, certificateRef));
			}
		}
		return relatedCertificates;
	}

	protected CertificateToken getUsedCertificateByCertificateRef(CertificateRef certificateRef) {
		CertificateTokenRefMatcher matcher = new CertificateTokenRefMatcher();
		for (CertificateToken certificateToken : usedCertificates) {
			if (matcher.match(certificateToken, certificateRef)) {
				return certificateToken;
			}
		}
		return null;
	}

	protected void verifyAgainstCertificateToken(XmlCertificateRef xmlCertificateRef, CertificateRef ref,
												 CertificateToken signingCertificate) {
		CertificateTokenRefMatcher tokenRefMatcher = new CertificateTokenRefMatcher();
		XmlDigestAlgoAndValue digestAlgoAndValue = xmlCertificateRef.getDigestAlgoAndValue();
		if (digestAlgoAndValue != null) {
			digestAlgoAndValue
					.setMatch(signingCertificate != null && tokenRefMatcher.matchByDigest(signingCertificate, ref));
		}
		XmlIssuerSerial issuerSerial = xmlCertificateRef.getIssuerSerial();
		if (issuerSerial != null) {
			issuerSerial
					.setMatch(signingCertificate != null && tokenRefMatcher.matchByIssuerName(signingCertificate, ref)
							&& tokenRefMatcher.matchBySerialNumber(signingCertificate, ref));
		}
	}

	private XmlIssuerSerial getXmlIssuerSerial(CertificateIdentifier certificateIdentifier) {
		XmlIssuerSerial xmlIssuerSerial = new XmlIssuerSerial();
		xmlIssuerSerial.setValue(certificateIdentifier.getIssuerSerialEncoded());
		return xmlIssuerSerial;
	}

	protected XmlBasicSignature getXmlBasicSignature(final Token token) {
		final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();

		SignatureAlgorithm signatureAlgorithm = token.getSignatureAlgorithm();
		if (signatureAlgorithm != null) {
			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm());
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm());
			xmlBasicSignatureType
					.setMaskGenerationFunctionUsedToSignThisToken(signatureAlgorithm.getMaskGenerationFunction());
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

	protected XmlCertificate buildDetachedXmlCertificate(CertificateToken certToken) {
		final XmlCertificate xmlCert = new XmlCertificate();
		xmlCert.setId(certToken.getDSSIdAsString());

		X500PrincipalHelper subject = certToken.getSubject();
		xmlCert.getSubjectDistinguishedName()
				.add(getXmlDistinguishedName(X500Principal.CANONICAL, subject.getCanonical()));
		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, subject.getRFC2253()));

		X500PrincipalHelper issuer = certToken.getIssuer();
		xmlCert.getIssuerDistinguishedName()
				.add(getXmlDistinguishedName(X500Principal.CANONICAL, issuer.getCanonical()));
		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, issuer.getRFC2253()));

		xmlCert.setSerialNumber(certToken.getSerialNumber());

		xmlCert.setSubjectSerialNumber(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.SERIALNUMBER, subject));
		xmlCert.setTitle(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.T, subject));
		xmlCert.setCommonName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, subject));
		xmlCert.setLocality(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.L, subject));
		xmlCert.setState(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.ST, subject));
		xmlCert.setCountryName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, subject));
		xmlCert.setOrganizationIdentifier(
				DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.ORGANIZATION_IDENTIFIER, subject));
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
		xmlCert.setQCLimitValue(getQCLimitValue(certToken));

		xmlCert.setBasicSignature(getXmlBasicSignature(certToken));

		xmlCert.setQCStatementIds(getXmlOids(DSSASN1Utils.getQCStatementsIdList(certToken)));
		xmlCert.setQCTypes(getXmlOids(DSSASN1Utils.getQCTypesIdList(certToken)));
		xmlCert.setCertificatePolicies(getXmlCertificatePolicies(DSSASN1Utils.getCertificatePolicies(certToken)));
		xmlCert.setSemanticsIdentifier(getXmlOid(DSSASN1Utils.getSemanticsIdentifier(certToken)));

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(trustedCertSources.isTrusted(certToken));

		if (tokenExtractionStrategy.isCertificate()) {
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

	private XmlQCLimitValue getQCLimitValue(CertificateToken certToken) {
		QCLimitValue qcLimitValue = DSSASN1Utils.getQcLimitValue(certToken);
		if (qcLimitValue != null) {
			XmlQCLimitValue xmlQCLimitValue = new XmlQCLimitValue();
			xmlQCLimitValue.setCurrency(qcLimitValue.getCurrency());
			xmlQCLimitValue.setAmount(qcLimitValue.getAmount());
			xmlQCLimitValue.setExponent(qcLimitValue.getExponent());
			return xmlQCLimitValue;
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

			Map<TrustServiceProvider, List<TrustProperties>> servicesByProviders = classifyByServiceProvider(services);

			for (Entry<TrustServiceProvider, List<TrustProperties>> servicesByProvider : servicesByProviders
					.entrySet()) {

				List<TrustProperties> trustServices = servicesByProvider.getValue();
				XmlTrustedServiceProvider serviceProvider = buildXmlTrustedServiceProvider(
						trustServices.iterator().next());
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
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService = trustProperties
					.getTrustService();
			List<TrustServiceStatusAndInformationExtensions> serviceStatusAfterOfEqualsCertIssuance = trustService
					.getAfter(certToken.getNotBefore());
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
	private List<String> getQualifiers(TrustServiceStatusAndInformationExtensions serviceInfoStatus,
									   CertificateToken certificateToken) {
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

	protected XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(Digest digest) {
		if (digest == null) {
			return getXmlDigestAlgoAndValue(null, null);
		} else {
			return getXmlDigestAlgoAndValue(digest.getAlgorithm(), digest.getValue());
		}
	}

	protected XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(DigestAlgorithm digestAlgo, byte[] digestValue) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digestAlgo);
		xmlDigestAlgAndValue.setDigestValue(digestValue == null ? DSSUtils.EMPTY_BYTE_ARRAY : digestValue);
		return xmlDigestAlgAndValue;
	}

}
