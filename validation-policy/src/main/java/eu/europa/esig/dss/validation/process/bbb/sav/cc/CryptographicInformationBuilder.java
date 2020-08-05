package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.Date;
import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicInformation;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public class CryptographicInformationBuilder {
	
	private final XmlConclusion conclusion;
	private final CryptographicConstraint constraint;
	
	private final DigestAlgorithm digestAlgorithm;
	private final EncryptionAlgorithm encryptionAlgorithm;
	private final MaskGenerationFunction maskGenerationFunction;
	private final String keyLength;
	private final String objectDecription;
	
	public CryptographicInformationBuilder(TokenProxy token, XmlConclusion conclusion, CryptographicConstraint constraint) {
		this(token.getDigestAlgorithm(), token.getEncryptionAlgorithm(), token.getMaskGenerationFunction(), token.getKeyLengthUsedToSignThisToken(), 
				token.getId(), conclusion, constraint);
	}
	
	public CryptographicInformationBuilder(XmlDigestMatcher digestMatcher, XmlConclusion conclusion, CryptographicConstraint constraint) {
		this(digestMatcher.getDigestMethod(), null, null, null, getDigestMatcherDescription(digestMatcher), conclusion, constraint);
	}
	
	private static String getDigestMatcherDescription(XmlDigestMatcher digestMatcher) {
		StringBuilder description = new StringBuilder(digestMatcher.getType().name());
		if (Utils.isStringNotEmpty(digestMatcher.getName())) {
			description.append(" with name [").append(digestMatcher.getName()).append("]");
		}
		return description.toString();
	}
	
	private CryptographicInformationBuilder(DigestAlgorithm digestAlgorithm, EncryptionAlgorithm encryptionAlgorithm, MaskGenerationFunction maskGenerationFunction,
			String keyLength, String objectDecription, XmlConclusion conclusion, CryptographicConstraint constraint) {
		this.digestAlgorithm = digestAlgorithm;
		this.encryptionAlgorithm = encryptionAlgorithm;
		this.maskGenerationFunction = maskGenerationFunction;
		this.keyLength = keyLength;
		this.objectDecription =objectDecription;
		
		this.conclusion = conclusion;
		this.constraint = constraint;
	}
	
	public XmlCryptographicInformation build() {
		XmlCryptographicInformation cryptoInfo = new XmlCryptographicInformation();
		cryptoInfo.setAlgorithm(getAlgorithmURI());
		cryptoInfo.setKeyLength(keyLength);
		cryptoInfo.setSecure(isSecure(conclusion));
		cryptoInfo.setNotAfter(getNotAfter());
		cryptoInfo.setConcernedMaterial(objectDecription);
		return cryptoInfo;
	}

	private String getAlgorithmURI() {
		try {
			if (encryptionAlgorithm != null) {
				return getSignatureAlgorithmUri(digestAlgorithm, encryptionAlgorithm, maskGenerationFunction);
			} else {
				return getDigestAlgorithmUri(digestAlgorithm);
			}
		} catch (Exception e) {
			return "???";
		}
	}
	
	private String getSignatureAlgorithmUri(DigestAlgorithm digestAlgorithm, 
			EncryptionAlgorithm encryptionAlgorithm, MaskGenerationFunction maskGenerationFunction) {
		SignatureAlgorithm sigAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm, maskGenerationFunction);
		return sigAlgo.getUri() != null ? sigAlgo.getUri() : sigAlgo.getURIBasedOnOID();
	}
	
	private String getDigestAlgorithmUri(DigestAlgorithm digestAlgorithm) {
		return digestAlgorithm.getUri() != null ? digestAlgorithm.getUri() : digestAlgorithm.getOid();
	}
	
	private boolean isSecure(XmlConclusion conclusion) {
		return Indication.PASSED.equals(conclusion.getIndication());
	}
	
	private Date getNotAfter() {
		if (constraint != null) {
			Date notAfter = null;
			CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(constraint);
			Map<String, Date> expirationDates = wrapper.getExpirationTimes();
			String digestAlgoToFind = digestAlgorithm == null ? Utils.EMPTY_STRING : digestAlgorithm.getName();
			notAfter = expirationDates.get(digestAlgoToFind);
			String encryptionAlgoToFind = encryptionAlgorithm == null ? Utils.EMPTY_STRING : encryptionAlgorithm.name();
			int keySize = Utils.isStringDigits(keyLength) ? Integer.parseInt(keyLength) : 0;
			Date expirationEncryption = wrapper.getExpirationDate(encryptionAlgoToFind, keySize);
			if (notAfter != null && encryptionAlgorithm != null && (expirationEncryption == null || expirationEncryption.before(notAfter))) {
				notAfter = expirationEncryption;
			}
			return notAfter;
		}
		return null;
	}

}
