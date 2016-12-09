package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;

public abstract class AbstractTokenProxy implements TokenProxy {

	protected abstract XmlBasicSignatureType getCurrentBasicSignature();

	protected abstract XmlCertificateChainType getCurrentCertificateChain();

	protected abstract XmlSigningCertificateType getCurrentSigningCertificate();

	@Override
	public List<XmlChainCertificate> getCertificateChain() {
		if (getCurrentCertificateChain() != null) {
			return getCurrentCertificateChain().getChainCertificate();
		}
		return new ArrayList<XmlChainCertificate>();
	}

	@Override
	public List<String> getCertificateChainIds() {
		List<String> result = new ArrayList<String>();
		List<XmlChainCertificate> certificateChain = getCertificateChain();
		if (CollectionUtils.isNotEmpty(certificateChain)) {
			for (XmlChainCertificate xmlChainCertificate : certificateChain) {
				result.add(xmlChainCertificate.getId());
			}
		}
		return result;
	}

	@Override
	public boolean isReferenceDataFound() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && BooleanUtils.isTrue(basicSignature.isReferenceDataFound());
	}

	@Override
	public boolean isReferenceDataIntact() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && BooleanUtils.isTrue(basicSignature.isReferenceDataIntact());
	}

	@Override
	public boolean isSignatureIntact() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && BooleanUtils.isTrue(basicSignature.isSignatureIntact());
	}

	@Override
	public boolean isSignatureValid() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && BooleanUtils.isTrue(basicSignature.isSignatureValid());
	}

	@Override
	public String getDigestAlgoUsedToSignThisToken() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getDigestAlgoUsedToSignThisToken();
		}
		return StringUtils.EMPTY;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		String signatureDigestAlgorithmName = getDigestAlgoUsedToSignThisToken();
		return DigestAlgorithm.forName(signatureDigestAlgorithmName, null);
	}

	@Override
	public String getEncryptionAlgoUsedToSignThisToken() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getEncryptionAlgoUsedToSignThisToken();
		}
		return StringUtils.EMPTY;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		String encryptionAlgoUsedToSignThisToken = getEncryptionAlgoUsedToSignThisToken();
		return EncryptionAlgorithm.forName(encryptionAlgoUsedToSignThisToken, null);
	}

	@Override
	public String getKeyLengthUsedToSignThisToken() {
		XmlBasicSignatureType basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getKeyLengthUsedToSignThisToken();
		}
		return StringUtils.EMPTY;
	}

	@Override
	public boolean isIssuerSerialMatch() {
		XmlSigningCertificateType currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && BooleanUtils.isTrue(currentSigningCertificate.isIssuerSerialMatch());
	}

	@Override
	public boolean isAttributePresent() {
		XmlSigningCertificateType currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && BooleanUtils.isTrue(currentSigningCertificate.isAttributePresent());
	}

	@Override
	public boolean isDigestValueMatch() {
		XmlSigningCertificateType currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && BooleanUtils.isTrue(currentSigningCertificate.isDigestValueMatch());
	}

	@Override
	public boolean isDigestValuePresent() {
		XmlSigningCertificateType currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && BooleanUtils.isTrue(currentSigningCertificate.isDigestValuePresent());
	}

	@Override
	public String getSigningCertificateId() {
		XmlSigningCertificateType currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null) {
			return currentSigningCertificate.getId();
		}
		return StringUtils.EMPTY;
	}

	@Override
	public String getSigningCertificateSigned() {
		XmlSigningCertificateType currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null) {
			return currentSigningCertificate.getSigned();
		}
		return StringUtils.EMPTY;
	}

	@Override
	public String getLastChainCertificateId() {
		XmlChainCertificate item = getLastChainCertificate();
		return item == null ? StringUtils.EMPTY : item.getId();
	}

	@Override
	public String getFirstChainCertificateId() {
		XmlChainCertificate item = getFirstChainCertificate();
		return item == null ? StringUtils.EMPTY : item.getId();
	}

	@Override
	public String getLastChainCertificateSource() {
		XmlChainCertificate item = getLastChainCertificate();
		return item == null ? StringUtils.EMPTY : item.getSource();
	}

	public XmlChainCertificate getLastChainCertificate() {
		XmlCertificateChainType certificateChain = getCurrentCertificateChain();
		if ((certificateChain != null) && CollectionUtils.isNotEmpty(certificateChain.getChainCertificate())) {
			List<XmlChainCertificate> list = certificateChain.getChainCertificate();
			XmlChainCertificate lastItem = list.get(list.size() - 1);
			return lastItem;
		}
		return null;
	}

	public XmlChainCertificate getFirstChainCertificate() {
		XmlCertificateChainType certificateChain = getCurrentCertificateChain();
		if ((certificateChain != null) && CollectionUtils.isNotEmpty(certificateChain.getChainCertificate())) {
			List<XmlChainCertificate> list = certificateChain.getChainCertificate();
			return list.get(0);
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
