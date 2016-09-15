package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractTokenProxy implements TokenProxy {

	protected abstract XmlBasicSignature getCurrentBasicSignature();

	protected abstract List<XmlChainItem> getCurrentCertificateChain();

	protected abstract XmlSigningCertificate getCurrentSigningCertificate();

	@Override
	public List<XmlChainItem> getCertificateChain() {
		if (getCurrentCertificateChain() != null) {
			return getCurrentCertificateChain();
		}
		return new ArrayList<XmlChainItem>();
	}

	@Override
	public List<String> getCertificateChainIds() {
		List<String> result = new ArrayList<String>();
		List<XmlChainItem> certificateChain = getCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			for (XmlChainItem xmlChainCertificate : certificateChain) {
				result.add(xmlChainCertificate.getId());
			}
		}
		return result;
	}

	@Override
	public boolean isReferenceDataFound() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && Utils.isTrue(basicSignature.isReferenceDataFound());
	}

	@Override
	public boolean isReferenceDataIntact() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && Utils.isTrue(basicSignature.isReferenceDataIntact());
	}

	@Override
	public boolean isSignatureIntact() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && Utils.isTrue(basicSignature.isSignatureIntact());
	}

	@Override
	public boolean isSignatureValid() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && Utils.isTrue(basicSignature.isSignatureValid());
	}

	@Override
	public String getDigestAlgoUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getDigestAlgoUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		String signatureDigestAlgorithmName = getDigestAlgoUsedToSignThisToken();
		return DigestAlgorithm.forName(signatureDigestAlgorithmName, null);
	}

	@Override
	public String getEncryptionAlgoUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getEncryptionAlgoUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		String encryptionAlgoUsedToSignThisToken = getEncryptionAlgoUsedToSignThisToken();
		return EncryptionAlgorithm.forName(encryptionAlgoUsedToSignThisToken, null);
	}

	@Override
	public String getKeyLengthUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getKeyLengthUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public boolean isIssuerSerialMatch() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isIssuerSerialMatch());
	}

	@Override
	public boolean isAttributePresent() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isAttributePresent());
	}

	@Override
	public boolean isDigestValueMatch() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isDigestValueMatch());
	}

	@Override
	public boolean isDigestValuePresent() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isDigestValuePresent());
	}

	@Override
	public String getSigningCertificateId() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null) {
			return currentSigningCertificate.getId();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public String getSigningCertificateSigned() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null) {
			return currentSigningCertificate.getSigned();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public String getLastChainCertificateId() {
		XmlChainItem item = getLastChainCertificate();
		return item == null ? Utils.EMPTY_STRING : item.getId();
	}

	@Override
	public String getFirstChainCertificateId() {
		XmlChainItem item = getFirstChainCertificate();
		return item == null ? Utils.EMPTY_STRING : item.getId();
	}

	@Override
	public String getLastChainCertificateSource() {
		XmlChainItem item = getLastChainCertificate();
		return item == null ? Utils.EMPTY_STRING : item.getSource();
	}

	public XmlChainItem getLastChainCertificate() {
		List<XmlChainItem> certificateChain = getCurrentCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			XmlChainItem lastItem = certificateChain.get(certificateChain.size() - 1);
			return lastItem;
		}
		return null;
	}

	public XmlChainItem getFirstChainCertificate() {
		List<XmlChainItem> certificateChain = getCurrentCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			return certificateChain.get(0);
		}
		return null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AbstractTokenProxy other = (AbstractTokenProxy) obj;
		if (getId() == null) {
			if (other.getId() != null)
				return false;
		} else if (!getId().equals(other.getId()))
			return false;
		return true;
	}

}
