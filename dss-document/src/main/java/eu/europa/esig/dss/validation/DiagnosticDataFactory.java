package eu.europa.esig.dss.validation;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlMessage;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureProductionPlace;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjects;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.Token;

/**
 * This class is used to build JAXB objects from the DSS model
 * 
 */
public class DiagnosticDataFactory {

	private static final Logger LOG = LoggerFactory.getLogger(DiagnosticDataFactory.class);

	public XmlRevocation getXmlRevocation(RevocationToken revocationToken, String xmlId, Set<DigestAlgorithm> usedDigestAlgorithms) {
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

	public List<XmlDigestAlgoAndValue> getXmlDigestAlgoAndValues(Set<DigestAlgorithm> usedDigestAlgorithms, Token token) {
		List<XmlDigestAlgoAndValue> result = new ArrayList<XmlDigestAlgoAndValue>();
		for (final DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {
			final XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
			xmlDigestAlgAndValue.setDigestMethod(digestAlgorithm.getName());
			xmlDigestAlgAndValue.setDigestValue(DSSUtils.digest(digestAlgorithm, token));
			result.add(xmlDigestAlgAndValue);
		}
		return result;
	}

	public List<XmlMessage> getXmlInfo(List<String> infos) {
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

	public List<XmlChainItem> getXmlForCertificateChain(CertificateToken token) {
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
	public XmlSigningCertificate getXmlSigningCertificate(CertificateToken token) {
		if (token != null) {
			final XmlSigningCertificate xmlSignCertType = new XmlSigningCertificate();
			xmlSignCertType.setId(token.getDSSIdAsString());
			return xmlSignCertType;
		}
		return null;
	}

	public XmlSigningCertificate getXmlSigningCertificate(CertificateValidity theCertificateValidity) {
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

	public XmlSignatureProductionPlace getXmlSignatureProductionPlace(SignatureProductionPlace signatureProductionPlace) {
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

	public List<XmlCertifiedRole> getXmlCertifiedRoles(List<CertifiedRole> certifiedRoles) {
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

	public List<String> getXmlClaimedRole(String[] claimedRoles) {
		if (Utils.isArrayNotEmpty(claimedRoles)) {
			return Arrays.asList(claimedRoles);
		}
		return Collections.emptyList();
	}

	public List<String> getXmlCommitmentTypeIndication(CommitmentType commitmentTypeIndication) {
		if (commitmentTypeIndication != null) {
			return commitmentTypeIndication.getIdentifiers();
		}
		return Collections.emptyList();
	}

	public String getXmlSignatureFormat(SignatureLevel signatureLevel) {
		return signatureLevel == null ? "UNKNOWN" : signatureLevel.name();
	}

	public XmlDistinguishedName getXmlDistinguishedName(final String x500PrincipalFormat, final X500Principal X500PrincipalName) {
		final XmlDistinguishedName xmlDistinguishedName = new XmlDistinguishedName();
		xmlDistinguishedName.setFormat(x500PrincipalFormat);
		xmlDistinguishedName.setValue(X500PrincipalName.getName(x500PrincipalFormat));
		return xmlDistinguishedName;
	}

	public XmlTimestamp getXmlTimestamp(final TimestampToken timestampToken) {

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

					final XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
					xmlDigestAlgAndValue.setDigestMethod(timestampReference.getDigestAlgorithm().getName());
					xmlDigestAlgAndValue.setDigestValue(timestampReference.getDigestValue());
					xmlDigestAlgAndValue.setCategory(timestampedCategory.name());
					xmlDigestAlgAndValueList.add(xmlDigestAlgAndValue);
				}
			}
			return xmlSignedObjectsType;
		}
		return null;
	}

	public XmlBasicSignature getXmlBasicSignature(final Token token) {
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

	public List<String> getXmlKeyUsages(Set<KeyUsageBit> keyUsageBits) {
		final List<String> xmlKeyUsageBitItems = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(keyUsageBits)) {
			for (final KeyUsageBit keyUsageBit : keyUsageBits) {
				xmlKeyUsageBitItems.add(keyUsageBit.name());
			}
		}
		return xmlKeyUsageBitItems;
	}

	public XmlBasicSignature getXmlBasicSignature(AdvancedSignature signature, SignatureCryptographicVerification scv,
			CertificateToken signingCertificateToken) {

		XmlBasicSignature xmlBasicSignature = new XmlBasicSignature();

		final EncryptionAlgorithm encryptionAlgorithm = signature.getEncryptionAlgorithm();
		final String encryptionAlgorithmString = encryptionAlgorithm == null ? "?" : encryptionAlgorithm.getName();
		xmlBasicSignature.setEncryptionAlgoUsedToSignThisToken(encryptionAlgorithmString);

		final int keyLength = signingCertificateToken == null ? 0 : DSSPKUtils.getPublicKeySize(signingCertificateToken.getPublicKey());
		xmlBasicSignature.setKeyLengthUsedToSignThisToken(String.valueOf(keyLength));
		final DigestAlgorithm digestAlgorithm = getDigestAlgorithm(signature);
		final String digestAlgorithmString = digestAlgorithm == null ? "?" : digestAlgorithm.getName();
		xmlBasicSignature.setDigestAlgoUsedToSignThisToken(digestAlgorithmString);

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

	public List<XmlSignatureScope> getXmlSignatureScopes(List<SignatureScope> scopes) {
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

	public XmlCertificate getXmlCertificate(Set<DigestAlgorithm> usedDigestAlgorithms, CertificateToken certToken) {
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

}
