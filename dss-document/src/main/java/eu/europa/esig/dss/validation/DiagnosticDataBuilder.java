package eu.europa.esig.dss.validation;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

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
import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
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
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.Token;

/**
 * This class is used to build JAXB objects from the DSS model
 * 
 */
public class DiagnosticDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(DiagnosticDataBuilder.class);

	private DSSDocument signedDocument;
	private List<AdvancedSignature> signatures;
	private Set<CertificateToken> usedCertificates;
	private Date validationDate;

	public void setSignedDocument(DSSDocument signedDocument) {
		this.signedDocument = signedDocument;
	}

	public void setSignatures(List<AdvancedSignature> signatures) {
		this.signatures = signatures;
	}

	public void setUsedCertificates(Set<CertificateToken> usedCertificates) {
		this.usedCertificates = usedCertificates;
	}

	public void setValidationDate(Date validationDate) {
		this.validationDate = validationDate;
	}

	public DiagnosticData build() {
		DiagnosticData diagnosticData = prepareDiagnosticData();

		Set<DigestAlgorithm> allUsedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();
		for (AdvancedSignature advancedSignature : signatures) {
			allUsedCertificatesDigestAlgorithms.addAll(advancedSignature.getUsedCertificatesDigestAlgorithms());

			XmlSignature xmlSignature = getXmlSignature(advancedSignature);
			xmlSignature.setTimestamps(getXmlTimestamps(advancedSignature));

			diagnosticData.getSignatures().add(xmlSignature);
		}

		for (CertificateToken certificateToken : usedCertificates) {
			XmlCertificate xmlCertificate = getXmlCertificate(allUsedCertificatesDigestAlgorithms, certificateToken);
			xmlCertificate.getTrustedServiceProvider().addAll(getXmlTrustedServiceProviders(certificateToken));
			diagnosticData.getUsedCertificates().add(xmlCertificate);
		}

		return diagnosticData;
	}

	private XmlSignature getXmlSignature(AdvancedSignature signature) {
		XmlSignature xmlSignature = new XmlSignature();

		final AdvancedSignature masterSignature = signature.getMasterSignature();
		if (masterSignature != null) {
			xmlSignature.setType(AttributeValue.COUNTERSIGNATURE);
			xmlSignature.setParentId(masterSignature.getId());
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

		// signingCertificateValidity can be null in case of a non AdES signature.

		xmlSignature.setCertificateChain(getXmlForCertificateChain(signingCertificateToken));

		xmlSignature.setBasicSignature(getXmlBasicSignature(signature, signingCertificateToken));

		xmlSignature.setPolicy(getXmlPolicy(signature.getPolicyId()));

		// if (signatureScopeFinder != null) {
		// xmlSignature.setSignatureScopes(getXmlSignatureScopes(signatureScopeFinder.findSignatureScope(signature)));
		// }

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
	 * This method prepares the {@code DiagnosticData} object to store all
	 * static information about the signatures being validated.
	 */
	private DiagnosticData prepareDiagnosticData() {
		DiagnosticData jaxbDiagnosticData = new DiagnosticData();

		String absolutePath = signedDocument.getAbsolutePath();
		String documentName = signedDocument.getName();
		if (Utils.isStringNotEmpty(absolutePath)) {
			jaxbDiagnosticData.setDocumentName(removeSpecialCharsForXml(absolutePath));
		} else if (Utils.isStringNotEmpty(documentName)) {
			jaxbDiagnosticData.setDocumentName(removeSpecialCharsForXml(documentName));
		} else {
			jaxbDiagnosticData.setDocumentName("?");
		}

		jaxbDiagnosticData.setValidationDate(validationDate);
		return jaxbDiagnosticData;
	}

	/**
	 * Escape special characters which cause problems with jaxb or
	 * documentbuilderfactory and namespace aware mode
	 */
	private String removeSpecialCharsForXml(String text) {
		return text.replaceAll("&", "");
	}

	private XmlRevocation getXmlRevocation(RevocationToken revocationToken, String xmlId, Set<DigestAlgorithm> usedDigestAlgorithms) {
		final XmlRevocation xmlRevocation = new XmlRevocation();
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
		xmlRevocation.setReason(revocationToken.getReason());
		xmlRevocation.setSource(revocationToken.getClass().getSimpleName());

		String sourceURL = revocationToken.getSourceURL();
		if (Utils.isStringNotEmpty(sourceURL)) { // not empty = online
			xmlRevocation.setSourceAddress(sourceURL);
			xmlRevocation.setAvailable(revocationToken.isAvailable());
		}

		xmlRevocation.setBasicSignature(getXmlBasicSignature(revocationToken));

		xmlRevocation.setDigestAlgoAndValues(getXmlDigestAlgoAndValues(usedDigestAlgorithms, revocationToken));

		final CertificateToken issuerToken = revocationToken.getIssuerToken();
		xmlRevocation.setSigningCertificate(getXmlSigningCertificate(issuerToken));
		xmlRevocation.setCertificateChain(getXmlForCertificateChain(issuerToken));
		xmlRevocation.setInfo(getXmlInfo(revocationToken.getValidationInfo()));

		return xmlRevocation;
	}

	private List<XmlDigestAlgoAndValue> getXmlDigestAlgoAndValues(Set<DigestAlgorithm> usedDigestAlgorithms, Token token) {
		List<XmlDigestAlgoAndValue> result = new ArrayList<XmlDigestAlgoAndValue>();
		for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {
			result.add(getXmlDigestAlgoAndValue(digestAlgorithm, DSSUtils.digest(digestAlgorithm, token)));
		}
		return result;
	}

	private List<XmlMessage> getXmlInfo(List<String> infos) {
		List<XmlMessage> messages = new ArrayList<XmlMessage>();
		if (Utils.isCollectionNotEmpty(infos)) {
			int i = 0;
			for (String message : infos) {
				final XmlMessage xmlMessage = new XmlMessage();
				xmlMessage.setId(i);
				xmlMessage.setValue(message);
				messages.add(xmlMessage);
				i++;
			}
		}
		return messages;
	}

	private List<XmlChainItem> getXmlForCertificateChain(CertificateToken token) {
		if (token != null) {

			CertificateToken issuerToken_ = token;
			final List<XmlChainItem> certChainTokens = new ArrayList<XmlChainItem>();
			do {

				certChainTokens.add(getXmlChainItem(issuerToken_));
				if (issuerToken_.isTrusted() || issuerToken_.isSelfSigned()) {

					break;
				}
				issuerToken_ = issuerToken_.getIssuerToken();
			} while (issuerToken_ != null);
			return certChainTokens;
		}
		return null;
	}

	private XmlChainItem getXmlChainItem(CertificateToken token) {
		final XmlChainItem chainItem = new XmlChainItem();
		chainItem.setId(token.getDSSId().asXmlId());
		chainItem.setSource(getCertificateMainSourceType(token).name());
		return chainItem;
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
	 * This method creates the SigningCertificate element for the current token.
	 *
	 * @param token
	 *            the token
	 * @return
	 */
	private XmlSigningCertificate getXmlSigningCertificate(CertificateToken token) {
		if (token != null) {
			final XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
			xmlSignCertType.setId(token.getDSSIdAsString());
			return xmlSignCertType;
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
		xmlSignCertType.setSigned(theCertificateValidity.getSigned());
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
		return signatureLevel == null ? "UNKNOWN" : signatureLevel.name();
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
	 *            The Signature Policy
	 * 
	 */
	private XmlPolicy getXmlPolicy(SignaturePolicy signaturePolicy) {
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

		/**
		 * ETSI 102 853: 3) Obtain the digest of the resulting document against
		 * which the digest value present in the property/attribute will be
		 * checked:
		 */
		final DSSDocument policyContent = signaturePolicy.getPolicyContent();
		byte[] policyBytes = null;
		if (policyContent == null) {
			xmlPolicy.setIdentified(false);
			if (policyId.isEmpty()) {
				xmlPolicy.setStatus(true);
			} else {
				xmlPolicy.setStatus(false);
			}
			return xmlPolicy;
		} else {
			policyBytes = DSSUtils.toByteArray(policyContent);
			xmlPolicy.setStatus(true);
		}
		xmlPolicy.setIdentified(true);

		if (Utils.isArrayEmpty(policyBytes)) {
			xmlPolicy.setIdentified(false);
			xmlPolicy.setProcessingError("Empty content for policy");
			return xmlPolicy;
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
					return xmlPolicy;
				} else {
					xmlPolicy.setDigestAlgorithmsEqual(true);
				}

				String recalculatedDigestValue = DatatypeConverter
						.printBase64Binary(DSSASN1Utils.getAsn1SignaturePolicyDigest(signPolicyHashAlgFromPolicy, policyBytes));

				boolean equal = Utils.areStringsEqual(digestValue, recalculatedDigestValue);
				xmlPolicy.setStatus(equal);
				if (!equal) {
					xmlPolicy.setProcessingError(
							"The policy digest value (" + digestValue + ") does not match the re-calculated digest value (" + recalculatedDigestValue + ").");
					return xmlPolicy;
				}

				final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
				final String policyDigestValueFromPolicy = DatatypeConverter.printBase64Binary(signPolicyHash.getOctets());
				equal = Utils.areStringsEqual(digestValue, policyDigestValueFromPolicy);
				xmlPolicy.setStatus(equal);
				if (!equal) {
					xmlPolicy.setProcessingError("The policy digest value (" + digestValue + ") does not match the digest value from the policy file ("
							+ policyDigestValueFromPolicy + ").");
				}
			} else {
				/**
				 * c) In all other cases, compute the digest using the digesting
				 * algorithm indicated in the children of the
				 * property/attribute.
				 */
				String recalculatedDigestValue = DatatypeConverter.printBase64Binary(DSSUtils.digest(signPolicyHashAlgFromSignature, policyBytes));
				boolean equal = Utils.areStringsEqual(digestValue, recalculatedDigestValue);
				xmlPolicy.setStatus(equal);
				if (!equal) {
					xmlPolicy.setProcessingError(
							"The policy digest value (" + digestValue + ") does not match the re-calculated digest value (" + recalculatedDigestValue + ").");
				}
			}

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
		xmlTimestampToken.setSignedDataDigestAlgo(timestampToken.getSignedDataDigestAlgo().getName());
		xmlTimestampToken.setEncodedSignedDataDigestValue(timestampToken.getEncodedSignedDataDigestValue());
		xmlTimestampToken.setMessageImprintDataFound(timestampToken.isMessageImprintDataFound());
		xmlTimestampToken.setMessageImprintDataIntact(timestampToken.isMessageImprintDataIntact());
		xmlTimestampToken.setCanonicalizationMethod(timestampToken.getCanonicalizationMethod());
		xmlTimestampToken.setBasicSignature(getXmlBasicSignature(timestampToken));

		final CertificateToken issuerToken = timestampToken.getIssuerToken();

		xmlTimestampToken.setSigningCertificate(getXmlSigningCertificate(issuerToken));
		xmlTimestampToken.setCertificateChain(getXmlForCertificateChain(issuerToken));
		xmlTimestampToken.setSignedObjects(getXmlSignedObjects(timestampToken.getTimestampedReferences()));

		return xmlTimestampToken;
	}

	private XmlSignedObjects getXmlSignedObjects(List<TimestampReference> timestampReferences) {
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

					final XmlDigestAlgoAndValue xmlDigestAlgAndValue = getXmlDigestAlgoAndValue(timestampReference.getDigestAlgorithm(),
							timestampReference.getDigestValue());
					xmlDigestAlgAndValue.setCategory(timestampedCategory.name());
					xmlDigestAlgAndValueList.add(xmlDigestAlgAndValue);
				}
			}
			return xmlSignedObjectsType;
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
		xmlBasicSignatureType.setReferenceDataFound(signatureValid);
		xmlBasicSignatureType.setReferenceDataIntact(signatureValid);
		xmlBasicSignatureType.setSignatureIntact(signatureValid);
		xmlBasicSignatureType.setSignatureValid(signatureValid);
		return xmlBasicSignatureType;
	}

	private List<String> getXmlKeyUsages(Set<KeyUsageBit> keyUsageBits) {
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
		final DigestAlgorithm digestAlgorithm = getDigestAlgorithm(signature);
		final String digestAlgorithmString = digestAlgorithm == null ? "?" : digestAlgorithm.getName();
		xmlBasicSignature.setDigestAlgoUsedToSignThisToken(digestAlgorithmString);

		SignatureCryptographicVerification scv = signature.getSignatureCryptographicVerification();
		xmlBasicSignature.setReferenceDataFound(scv.isReferenceDataFound());
		xmlBasicSignature.setReferenceDataIntact(scv.isReferenceDataIntact());
		xmlBasicSignature.setSignatureIntact(scv.isSignatureIntact());
		xmlBasicSignature.setSignatureValid(scv.isSignatureValid());
		return xmlBasicSignature;
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

	private List<XmlSignatureScope> getXmlSignatureScopes(List<SignatureScope> scopes) {
		List<XmlSignatureScope> xmlScopes = new ArrayList<XmlSignatureScope>();
		for (SignatureScope xmlSignatureScope : scopes) {
			xmlScopes.add(getXmlSignatureScope(xmlSignatureScope));
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

		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.CANONICAL, certToken.getSubjectX500Principal()));
		xmlCert.getSubjectDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, certToken.getSubjectX500Principal()));

		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.CANONICAL, certToken.getIssuerX500Principal()));
		xmlCert.getIssuerDistinguishedName().add(getXmlDistinguishedName(X500Principal.RFC2253, certToken.getIssuerX500Principal()));

		xmlCert.setSerialNumber(certToken.getSerialNumber());

		X500Principal x500Principal = certToken.getSubjectX500Principal();
		xmlCert.setCommonName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, x500Principal));
		xmlCert.setCountryName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.C, x500Principal));
		xmlCert.setOrganizationName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, x500Principal));
		xmlCert.setGivenName(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.GIVENNAME, x500Principal));
		xmlCert.setOrganizationalUnit(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.OU, x500Principal));
		xmlCert.setSurname(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.SURNAME, x500Principal));
		xmlCert.setPseudonym(DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.PSEUDONYM, x500Principal));

		xmlCert.setDigestAlgoAndValues(getXmlDigestAlgoAndValues(usedDigestAlgorithms, certToken));

		xmlCert.setNotAfter(certToken.getNotAfter());
		xmlCert.setNotBefore(certToken.getNotBefore());
		final PublicKey publicKey = certToken.getPublicKey();
		xmlCert.setPublicKeySize(DSSPKUtils.getPublicKeySize(publicKey));
		xmlCert.setPublicKeyEncryptionAlgo(DSSPKUtils.getPublicKeyEncryptionAlgo(publicKey));

		xmlCert.setKeyUsageBits(getXmlKeyUsages(certToken.getKeyUsageBits()));

		xmlCert.setIdKpOCSPSigning(DSSASN1Utils.isOCSPSigning(certToken));
		xmlCert.setIdPkixOcspNoCheck(DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certToken));

		xmlCert.setBasicSignature(getXmlBasicSignature(certToken));

		final CertificateToken issuerToken = certToken.getIssuerToken();
		xmlCert.setSigningCertificate(getXmlSigningCertificate(issuerToken));
		xmlCert.setCertificateChain(getXmlForCertificateChain(issuerToken));

		xmlCert.setQCStatementIds(DSSASN1Utils.getQCStatementsIdList(certToken));
		xmlCert.setQCTypes(DSSASN1Utils.getQCTypesIdList(certToken));
		xmlCert.setCertificatePolicyIds(DSSASN1Utils.getPolicyIdentifiers(certToken));

		xmlCert.setSelfSigned(certToken.isSelfSigned());
		xmlCert.setTrusted(certToken.isTrusted());
		xmlCert.setInfo(getXmlInfo(certToken.getValidationInfo()));

		final Set<RevocationToken> revocationTokens = certToken.getRevocationTokens();
		if (Utils.isCollectionNotEmpty(revocationTokens)) {
			for (RevocationToken revocationToken : revocationTokens) {
				// In case of CRL, the X509CRL can be the same for different certificates
				byte[] digestForId = DSSUtils.digest(DigestAlgorithm.SHA256, certToken.getEncoded(), revocationToken.getEncoded());
				String xmlId = DatatypeConverter.printHexBinary(digestForId);
				xmlCert.getRevocation().add(getXmlRevocation(revocationToken, xmlId, usedDigestAlgorithms));
			}
		}

		return xmlCert;
	}

	/**
	 * This method deals with the trusted service information in case of trusted
	 * certificate. The retrieved information is transformed to the JAXB object.
	 *
	 * @param certToken
	 * @param xmlCert
	 */
	private List<XmlTrustedServiceProvider> getXmlTrustedServiceProviders(final CertificateToken certToken) {
		Set<ServiceInfo> services = null;
		if (certToken.isTrusted()) {
			services = certToken.getAssociatedTSPS();
		} else {
			final CertificateToken trustAnchor = certToken.getTrustAnchor();
			if (trustAnchor != null) {
				services = trustAnchor.getAssociatedTSPS();
			}
		}
		List<XmlTrustedServiceProvider> xmlTSPs = new ArrayList<XmlTrustedServiceProvider>();
		if (Utils.isCollectionNotEmpty(services)) {
			for (final ServiceInfo serviceInfo : services) {
				xmlTSPs.add(getXmlTrustedServiceProvider(serviceInfo, certToken));
			}
		}
		return xmlTSPs;
	}

	private XmlTrustedServiceProvider getXmlTrustedServiceProvider(final ServiceInfo serviceInfo, final CertificateToken certToken) {
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
		return xmlTSP;
	}

	/**
	 * Retrieves all the qualifiers for which the corresponding conditionEntry
	 * is true.
	 *
	 * @param certificateToken
	 * @return
	 */
	private List<String> getQualifiers(ServiceInfoStatus serviceStatusAtCertIssuance, CertificateToken certificateToken) {
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

	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(DigestAlgorithm digestAlgo, String digestValue) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digestAlgo == null ? "" : digestAlgo.getName());
		xmlDigestAlgAndValue.setDigestValue(digestValue);
		return xmlDigestAlgAndValue;
	}

}
