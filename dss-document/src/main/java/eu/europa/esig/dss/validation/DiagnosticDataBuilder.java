package eu.europa.esig.dss.validation;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
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

import eu.europa.esig.dss.CertificatePolicy;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificatePolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlContainerInfo;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlManifestFile;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureProductionPlace;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.tsl.TLInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;

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
	private boolean includeRawRevocationData = false;

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

	public DiagnosticData build() {
		DiagnosticData diagnosticData = new DiagnosticData();
		if (signedDocument != null) {
			diagnosticData.setDocumentName(removeSpecialCharsForXml(signedDocument.getName()));
		}
		diagnosticData.setValidationDate(validationDate);
		diagnosticData.setContainerInfo(getXmlContainerInfo());

		Set<DigestAlgorithm> allUsedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature advancedSignature : signatures) {
				allUsedCertificatesDigestAlgorithms.addAll(advancedSignature.getUsedCertificatesDigestAlgorithms());

				diagnosticData.getSignatures().add(getXmlSignature(advancedSignature));
			}
		}

		List<XmlCertificate> xmlCertificates = new ArrayList<XmlCertificate>();
		Set<String> countryCodes = new HashSet<String>();
		if (Utils.isCollectionNotEmpty(usedCertificates)) {
			for (CertificateToken certificateToken : usedCertificates) {
				xmlCertificates.add(getXmlCertificate(allUsedCertificatesDigestAlgorithms, certificateToken));

				if (trustedCertSource != null) {
					Set<ServiceInfo> associatedTSPS = trustedCertSource.getTrustServices(certificateToken);
					if (Utils.isCollectionNotEmpty(associatedTSPS)) {
						for (ServiceInfo serviceInfo : associatedTSPS) {
							countryCodes.add(serviceInfo.getTlCountryCode());
						}
					}
				}
			}
		}
		diagnosticData.setUsedCertificates(Collections.unmodifiableList(xmlCertificates));

		if (trustedCertSource instanceof TrustedListsCertificateSource) {
			TrustedListsCertificateSource tlCS = (TrustedListsCertificateSource) trustedCertSource;
			boolean addLOTL = false;
			for (String countryCode : countryCodes) {
				TLInfo tlInfo = tlCS.getTlInfo(countryCode);
				if (tlInfo != null) {
					diagnosticData.getTrustedLists().add(getXmlTrustedList(countryCode, tlInfo));
					addLOTL = true;
				}
			}

			if (addLOTL) {
				diagnosticData.setListOfTrustedLists(getXmlTrustedList("LOTL", tlCS.getLotlInfo()));
			}
		}

		return diagnosticData;
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

	private XmlSignature getXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = new XmlSignature();

		xmlSignature.setSignatureFilename(removeSpecialCharsForXml(signature.getSignatureFilename()));

		final AdvancedSignature masterSignature = signature.getMasterSignature();
		if (masterSignature != null) {
			xmlSignature.setCounterSignature(true);
			xmlSignature.setParentId(masterSignature.getId());
			xmlSignature.setSignatureFilename(removeSpecialCharsForXml(masterSignature.getSignatureFilename()));
		}
		xmlSignature.setId(signature.getId());
		xmlSignature.setDateTime(signature.getSigningTime());
		xmlSignature.setStructuralValidation(getXmlStructuralValidation(signature));
		xmlSignature.setSignatureFormat(getXmlSignatureFormat(signature.getDataFoundUpToLevel()));

		xmlSignature.setSignatureProductionPlace(getXmlSignatureProductionPlace(signature.getSignatureProductionPlace()));
		xmlSignature.setCommitmentTypeIndication(getXmlCommitmentTypeIndication(signature.getCommitmentTypeIndication()));
		xmlSignature.setClaimedRoles(getXmlClaimedRole(signature.getClaimedSignerRoles()));
		xmlSignature.getCertifiedRoles().addAll(getXmlCertifiedRoles(signature.getCertifiedSignerRoles()));

		xmlSignature.setContentType(signature.getContentType());
		xmlSignature.setContentIdentifier(signature.getContentIdentifier());
		xmlSignature.setContentHints(signature.getContentHints());

		CertificateToken signingCertificateToken = null;

		final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
		final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
		if (theCertificateValidity != null) {
			xmlSignature.setSigningCertificate(getXmlSigningCertificate(theCertificateValidity));
			signingCertificateToken = theCertificateValidity.getCertificateToken();
		}

		if (signingCertificateToken != null) {
			xmlSignature.setCertificateChain(getXmlForCertificateChain(signingCertificateToken.getPublicKey()));
			xmlSignature.setBasicSignature(getXmlBasicSignature(signature, signingCertificateToken));
		}
		xmlSignature.setDigestMatchers(getXmlDigestMatchers(signature));

		xmlSignature.setPolicy(getXmlPolicy(signature));

		xmlSignature.setTimestamps(getXmlTimestamps(signature));

		xmlSignature.setSignatureScopes(getXmlSignatureScopes(signature.getSignatureScopes()));

		return xmlSignature;
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

	private XmlRevocation getXmlRevocation(CertificateToken certToken, RevocationToken revocationToken, Set<DigestAlgorithm> usedDigestAlgorithms) {
		final XmlRevocation xmlRevocation = new XmlRevocation();

		// In case of CRL, the X509CRL can be the same for different certificates
		String xmlId = Utils.toHex(certToken.getDigest(DigestAlgorithm.SHA256)) + Utils.toHex(revocationToken.getDigest(DigestAlgorithm.SHA256));
		xmlRevocation.setId(xmlId);

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
		CRLReasonEnum reason = revocationToken.getReason();
		if (reason != null) {
			xmlRevocation.setReason(reason.name());
		}
		xmlRevocation.setSource(revocationToken.getClass().getSimpleName());

		String sourceURL = revocationToken.getSourceURL();
		if (Utils.isStringNotEmpty(sourceURL)) { // not empty = online
			xmlRevocation.setSourceAddress(sourceURL);
			xmlRevocation.setAvailable(revocationToken.isAvailable());
		}

		Digest certHash = revocationToken.getCertHash();
		if (certHash != null) {
			xmlRevocation.setCertHashExtensionPresent(true);
			byte[] expectedDigest = certToken.getDigest(certHash.getAlgorithm());
			byte[] foundDigest = certHash.getValue();
			xmlRevocation.setCertHashExtensionMatch(Arrays.equals(expectedDigest, foundDigest));
		}

		xmlRevocation.setBasicSignature(getXmlBasicSignature(revocationToken));

		xmlRevocation.setDigestAlgoAndValues(getXmlDigestAlgoAndValues(usedDigestAlgorithms, revocationToken));

		xmlRevocation.setSigningCertificate(getXmlSigningCertificate(revocationToken.getPublicKeyOfTheSigner()));
		xmlRevocation.setCertificateChain(getXmlForCertificateChain(revocationToken.getPublicKeyOfTheSigner()));
		
		if (includeRawRevocationData) {
			xmlRevocation.setBase64Encoded(revocationToken.getEncoded());
		}

		return xmlRevocation;
	}

	private List<XmlDigestAlgoAndValue> getXmlDigestAlgoAndValues(Set<DigestAlgorithm> usedDigestAlgorithms, Token token) {
		List<XmlDigestAlgoAndValue> result = new ArrayList<XmlDigestAlgoAndValue>();
		for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {
			result.add(getXmlDigestAlgoAndValue(digestAlgorithm, Utils.toBase64(token.getDigest(digestAlgorithm))));
		}
		return result;
	}

	private List<XmlChainItem> getXmlForCertificateChain(PublicKey certPubKey) {
		if (certPubKey != null) {
			final List<XmlChainItem> certChainTokens = new ArrayList<XmlChainItem>();
			Set<CertificateToken> processedTokens = new HashSet<CertificateToken>();
			CertificateToken issuerToken = getCertificateByPubKey(certPubKey);
			while (issuerToken !=null) {
				certChainTokens.add(getXmlChainItem(issuerToken));
				if (issuerToken.isSelfSigned() || processedTokens.contains(issuerToken)
						|| isTrusted(issuerToken)) {
					break;
				}
				processedTokens.add(issuerToken);
				issuerToken  = getCertificateByPubKey(issuerToken.getPublicKeyOfTheSigner());
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
		chainItem.setId(token.getDSSIdAsString());
		chainItem.setSource(getCertificateMainSourceType(token).name());
		return chainItem;
	}

	private CertificateSourceType getCertificateMainSourceType(final CertificateToken token) {
		CertificateSourceType mainSource = CertificateSourceType.UNKNOWN;
		if (certificateSourceTypes != null) {
			Set<CertificateSourceType> sourceTypes = certificateSourceTypes.get(token);
			if (sourceTypes.size() > 0) {
				if (sourceTypes.contains(CertificateSourceType.TRUSTED_LIST)) {
					mainSource = CertificateSourceType.TRUSTED_LIST;
				} else if (sourceTypes.contains(CertificateSourceType.TRUSTED_STORE)) {
					mainSource = CertificateSourceType.TRUSTED_STORE;
				} else {
					mainSource = sourceTypes.iterator().next();
				}
			}
		}
		return mainSource;
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
			xmlSignCertType.setId(certificateByPubKey.getDSSIdAsString());
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
			xmlSignCertType.setId(signingCertificateToken.getDSSIdAsString());
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
			xmlSignatureProductionPlace.setCountryName(signatureProductionPlace.getCountryName());
			xmlSignatureProductionPlace.setStateOrProvince(signatureProductionPlace.getStateOrProvince());
			xmlSignatureProductionPlace.setPostalCode(signatureProductionPlace.getPostalCode());
			xmlSignatureProductionPlace.setAddress(signatureProductionPlace.getStreetAddress());
			xmlSignatureProductionPlace.setCity(signatureProductionPlace.getCity());
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

	private List<XmlTimestamp> getXmlTimestamps(AdvancedSignature signature) {
		List<XmlTimestamp> xmlTimestamps = new ArrayList<XmlTimestamp>();
		xmlTimestamps.addAll(getXmlTimestamps(signature.getContentTimestamps()));
		xmlTimestamps.addAll(getXmlTimestamps(signature.getSignatureTimestamps()));
		xmlTimestamps.addAll(getXmlTimestamps(signature.getTimestampsX1()));
		xmlTimestamps.addAll(getXmlTimestamps(signature.getTimestampsX2()));
		xmlTimestamps.addAll(getXmlTimestamps(signature.getArchiveTimestamps()));
		return xmlTimestamps;
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

		final String notice = signaturePolicy.getNotice();
		xmlPolicy.setNotice(notice);

		final String digestValue = signaturePolicy.getDigestValue();
		final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();

		if (Utils.isStringNotEmpty(digestValue)) {
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
		List<XmlTimestamp> xmlTimestamps = new ArrayList<XmlTimestamp>();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampToken timestampToken : timestamps) {
				xmlTimestamps.add(getXmlTimestamp(timestampToken));
			}
		}
		return xmlTimestamps;
	}

	private XmlTimestamp getXmlTimestamp(final TimestampToken timestampToken) {

		final XmlTimestamp xmlTimestampToken = new XmlTimestamp();

		xmlTimestampToken.setId(timestampToken.getDSSIdAsString());
		xmlTimestampToken.setType(timestampToken.getTimeStampType().name());
		xmlTimestampToken.setProductionTime(timestampToken.getGenerationTime());
		xmlTimestampToken.setDigestMatcher(getXmlDigestMatcher(timestampToken));
		xmlTimestampToken.setBasicSignature(getXmlBasicSignature(timestampToken));

		xmlTimestampToken.setSigningCertificate(getXmlSigningCertificate(timestampToken.getPublicKeyOfTheSigner()));
		xmlTimestampToken.setCertificateChain(getXmlForCertificateChain(timestampToken.getPublicKeyOfTheSigner()));
		xmlTimestampToken.setTimestampedObjects(getXmlTimestampedObjects(timestampToken.getTimestampedReferences()));

		return xmlTimestampToken;
	}

	private XmlDigestMatcher getXmlDigestMatcher(TimestampToken timestampToken) {
		XmlDigestMatcher digestMatcher = new XmlDigestMatcher();
		digestMatcher.setType(DigestMatcherType.MESSAGE_IMPRINT);
		DigestAlgorithm digestAlgo = timestampToken.getSignedDataDigestAlgo();
		digestMatcher.setDigestMethod(digestAlgo == null ? "" : digestAlgo.getName());
		digestMatcher.setDigestValue(timestampToken.getEncodedSignedDataDigestValue());
		digestMatcher.setDataFound(timestampToken.isMessageImprintDataFound());
		digestMatcher.setDataIntact(timestampToken.isMessageImprintDataIntact());
		return digestMatcher;
	}

	private List<XmlTimestampedObject> getXmlTimestampedObjects(List<TimestampReference> timestampReferences) {
		if (Utils.isCollectionNotEmpty(timestampReferences)) {
			List<XmlTimestampedObject> objects = new ArrayList<XmlTimestampedObject>();
			for (final TimestampReference timestampReference : timestampReferences) {
				XmlTimestampedObject timestampedObject = new XmlTimestampedObject();

				final TimestampedObjectType timestampedCategory = timestampReference.getCategory();
				timestampedObject.setCategory(timestampReference.getCategory());
				if (TimestampedObjectType.SIGNATURE == timestampedCategory || TimestampedObjectType.TIMESTAMP == timestampedCategory) {
					timestampedObject.setId(timestampReference.getSignatureId());
				} else {
					// CERTIFICATE || REVOCATION
					timestampedObject
							.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(timestampReference.getDigestAlgorithm(), timestampReference.getDigestValue()));
				}

				objects.add(timestampedObject);
			}
			return objects;
		}
		return null;
	}

	private XmlBasicSignature getXmlBasicSignature(final Token token) {
		final XmlBasicSignature xmlBasicSignatureType = new XmlBasicSignature();

		SignatureAlgorithm signatureAlgorithm = token.getSignatureAlgorithm();
		if (signatureAlgorithm != null) {
			xmlBasicSignatureType.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgorithm().getName());
			xmlBasicSignatureType.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgorithm().getName());
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
			ref.setDigestValue(Utils.toBase64(digest.getValue()));
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
		xmlSignatureScope.setValue(scope.getDescription());
		return xmlSignatureScope;
	}

	private XmlCertificate getXmlCertificate(Set<DigestAlgorithm> usedDigestAlgorithms, CertificateToken certToken) {
		final XmlCertificate xmlCert = new XmlCertificate();

		xmlCert.setId(certToken.getDSSIdAsString());
		xmlCert.setBase64Encoded(certToken.getEncoded());

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

		xmlCert.setDigestAlgoAndValues(getXmlDigestAlgoAndValues(usedDigestAlgorithms, certToken));

		xmlCert.setNotAfter(certToken.getNotAfter());
		xmlCert.setNotBefore(certToken.getNotBefore());
		final PublicKey publicKey = certToken.getPublicKey();
		xmlCert.setPublicKeySize(DSSPKUtils.getPublicKeySize(publicKey));
		xmlCert.setPublicKeyEncryptionAlgo(EncryptionAlgorithm.forKey(publicKey).getName());

		xmlCert.setKeyUsageBits(getXmlKeyUsages(certToken.getKeyUsageBits()));
		xmlCert.setExtendedKeyUsages(getXmlOids(DSSASN1Utils.getExtendedKeyUsage(certToken)));

		xmlCert.setIdPkixOcspNoCheck(DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken));

		xmlCert.setBasicSignature(getXmlBasicSignature(certToken));

		xmlCert.setSigningCertificate(getXmlSigningCertificate(certToken.getPublicKeyOfTheSigner()));
		xmlCert.setCertificateChain(getXmlForCertificateChain(certToken.getPublicKeyOfTheSigner()));

		xmlCert.setQCStatementIds(getXmlOids(DSSASN1Utils.getQCStatementsIdList(certToken)));
		xmlCert.setQCTypes(getXmlOids(DSSASN1Utils.getQCTypesIdList(certToken)));
		xmlCert.setCertificatePolicies(getXmlCertificatePolicies(DSSASN1Utils.getCertificatePolicies(certToken)));

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(isTrusted(certToken));

		final Set<RevocationToken> revocationTokens = getRevocationsForCert(certToken);
		if (Utils.isCollectionNotEmpty(revocationTokens)) {
			for (RevocationToken revocationToken : revocationTokens) {
				xmlCert.getRevocations().add(getXmlRevocation(certToken, revocationToken, usedDigestAlgorithms));
			}
		}

		if (trustedCertSource != null) {
			xmlCert.setTrustedServiceProviders(getXmlTrustedServiceProviders(certToken));
		}
		return xmlCert;
	}

	private Set<RevocationToken> getRevocationsForCert(CertificateToken certToken) {
		Set<RevocationToken> revocations = new HashSet<RevocationToken>();
		for (RevocationToken revocationToken : usedRevocations) {
			if (Utils.areStringsEqual(certToken.getDSSIdAsString(), revocationToken.getRelatedCertificateID())) {
				revocations.add(revocationToken);
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
		Set<ServiceInfo> services = getRelatedTrustServices(certToken);
		Map<String, List<ServiceInfo>> servicesByProviders = classifyByServiceProvider(services);
		for (List<ServiceInfo> servicesByProvider : servicesByProviders.values()) {
			ServiceInfo first = servicesByProvider.get(0);
			XmlTrustedServiceProvider serviceProvider = new XmlTrustedServiceProvider();
			serviceProvider.setCountryCode(first.getTlCountryCode());
			serviceProvider.setTSPName(first.getTspName());
			serviceProvider.setTSPRegistrationIdentifier(first.getTspRegistrationIdentifier());
			serviceProvider.setTrustedServices(getXmlTrustedServices(servicesByProvider, certToken));
			result.add(serviceProvider);
		}
		return Collections.unmodifiableList(result);
	}

	private Set<ServiceInfo> getRelatedTrustServices(CertificateToken certToken) {
		if (trustedCertSource instanceof TrustedListsCertificateSource) {
			Set<ServiceInfo> result = new HashSet<ServiceInfo>();
			do {
				result.addAll(trustedCertSource.getTrustServices(certToken));
				PublicKey issuerPublicKey = certToken.getPublicKeyOfTheSigner();
				if (issuerPublicKey != null) {
					certToken = getCertificateByPubKey(issuerPublicKey);
				} else {
					certToken = null;
				}
			} while (certToken != null);
			return result;
		} else {
			return Collections.emptySet();
		}
	}

	private List<XmlTrustedService> getXmlTrustedServices(List<ServiceInfo> serviceInfos, CertificateToken certToken) {
		List<XmlTrustedService> result = new ArrayList<XmlTrustedService>();
		for (ServiceInfo serviceInfo : serviceInfos) {
			List<ServiceInfoStatus> serviceStatusAfterOfEqualsCertIssuance = serviceInfo.getStatus().getAfter(certToken.getNotBefore());
			if (Utils.isCollectionNotEmpty(serviceStatusAfterOfEqualsCertIssuance)) {
				for (ServiceInfoStatus serviceInfoStatus : serviceStatusAfterOfEqualsCertIssuance) {
					XmlTrustedService trustedService = new XmlTrustedService();

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

	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(DigestAlgorithm digestAlgo, String digestValue) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digestAlgo == null ? "" : digestAlgo.getName());
		xmlDigestAlgAndValue.setDigestValue(digestValue);
		return xmlDigestAlgAndValue;
	}

}
