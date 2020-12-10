package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * Builds the DiagnosticData for a CertificateToken validation
 */
public class CertificateDiagnosticDataBuilder extends DiagnosticDataBuilder {

	@Override
	public CertificateDiagnosticDataBuilder usedCertificates(Set<CertificateToken> usedCertificates) {
		return (CertificateDiagnosticDataBuilder) super.usedCertificates(usedCertificates);
	}

	@Override
	public CertificateDiagnosticDataBuilder certificateSourceTypes(
			Map<CertificateToken, Set<CertificateSourceType>> certificateSourceTypes) {
		return (CertificateDiagnosticDataBuilder) super.certificateSourceTypes(certificateSourceTypes);
	}

	@Override
	public CertificateDiagnosticDataBuilder usedRevocations(Set<RevocationToken<Revocation>> usedRevocations) {
		return (CertificateDiagnosticDataBuilder) super.usedRevocations(usedRevocations);
	}

	@Override
	public CertificateDiagnosticDataBuilder trustedCertificateSources(ListCertificateSource trustedCertSources) {
		return (CertificateDiagnosticDataBuilder) super.trustedCertificateSources(trustedCertSources);
	}

	@Override
	public CertificateDiagnosticDataBuilder validationDate(Date validationDate) {
		return (CertificateDiagnosticDataBuilder) super.validationDate(validationDate);
	}

	@Override
	public CertificateDiagnosticDataBuilder tokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		return (CertificateDiagnosticDataBuilder) super.tokenExtractionStrategy(tokenExtractionStrategy);
	}

	@Override
	public CertificateDiagnosticDataBuilder defaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (CertificateDiagnosticDataBuilder) super.defaultDigestAlgorithm(digestAlgorithm);
	}

}
