package eu.europa.esig.dss.validation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlKeyUsageBits;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQCStatement;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQualifiers;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;

public class CertificateWrapper extends AsbtractTokenProxy {

	private final XmlCertificate certificate;

	public CertificateWrapper(XmlCertificate certificate) {
		this.certificate = certificate;
	}

	@Override
	public String getId() {
		return certificate.getId();
	}

	@Override
	protected XmlBasicSignatureType getCurrentBasicSignature() {
		return certificate.getBasicSignature();
	}

	@Override
	protected XmlCertificateChainType getCurrentCertificateChain() {
		return certificate.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificateType getCurrentSigningCertificate() {
		return certificate.getSigningCertificate();
	}

	public boolean isTrusted() {
		return certificate.isTrusted();
	}

	public List<String> getKeyUsages() {
		List<String> keyUsages = new ArrayList<String>();
		XmlKeyUsageBits keyUsageBits = certificate.getKeyUsageBits();
		if ((keyUsageBits != null) && CollectionUtils.isNotEmpty(keyUsageBits.getKeyUsage())) {
			keyUsages.addAll(keyUsageBits.getKeyUsage());
		}
		return keyUsages;
	}

	public boolean isRevocationDataAvailable() {
		return certificate.getRevocation() != null;
	}

	public RevocationWrapper getRevocationData() {
		if (isRevocationDataAvailable()) {
			return new RevocationWrapper(certificate.getRevocation());
		}
		return null;
	}

	public Date getNotBefore() {
		return certificate.getNotBefore();
	}

	public Date getNotAfter() {
		return certificate.getNotAfter();
	}

	public boolean isCertificateQCP() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCP();
	}

	public boolean isCertificateQCPPlus() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCPPlus();
	}

	public boolean isCertificateQCC() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCC();
	}

	public boolean isCertificateQCSSCD() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCSSCD();
	}

	public List<String> getCertificateTSPServiceQualifiers() {
		Set<String> result = new HashSet<String>();
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType xmlTrustedServiceProvider : trustedServiceProviders) {
				XmlQualifiers qualifiers = xmlTrustedServiceProvider.getQualifiers();
				if ((qualifiers != null) && CollectionUtils.isNotEmpty(qualifiers.getQualifier())) {
					for (String qualifier : qualifiers.getQualifier()) {
						result.add(qualifier);
					}
				}
			}
		}
		return new ArrayList<String>(result);
	}

	public String getCertificateTSPServiceStatus() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getStatus(); // TODO correct ?? return first one
			}
		}
		return StringUtils.EMPTY;
	}

	public Date getCertificateTSPServiceStartDate() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getStartDate(); // TODO correct ?? return first one
			}
		}
		return null;
	}

	public Date getCertificateTSPServiceEndDate() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getEndDate(); // TODO correct ?? return first one
			}
		}
		return null;
	}

	public String getCertificateTSPServiceName() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getTSPServiceName(); // TODO correct ?? return first one
			}
		}
		return StringUtils.EMPTY;
	}

	public boolean isRevoked() {
		if ((certificate != null) && (certificate.getRevocation() != null)) {
			return certificate.getRevocation().isStatus();
		}
		return false;
	}

	public boolean isValidCertificate() {
		final boolean signatureValid = (certificate.getBasicSignature() != null) && certificate.getBasicSignature().isSignatureValid();
		final boolean revocationValid = (certificate.getRevocation() != null) && certificate.getRevocation().isStatus();
		final boolean trusted = certificate.isTrusted();

		final boolean validity = signatureValid && (trusted ? true : revocationValid);
		return validity;
	}

	public String getSerialNumber() {
		BigInteger serialNumber = certificate.getSerialNumber();
		return serialNumber == null ? StringUtils.EMPTY : serialNumber.toString();
	}

}
