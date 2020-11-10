package eu.europa.esig.dss.validation;

import java.util.Date;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

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
	public CertificateDiagnosticDataBuilder tokenExtractionStategy(TokenExtractionStategy tokenExtractionStategy) {
		return (CertificateDiagnosticDataBuilder) super.tokenExtractionStategy(tokenExtractionStategy);
	}

	@Override
	public CertificateDiagnosticDataBuilder defaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (CertificateDiagnosticDataBuilder) super.defaultDigestAlgorithm(digestAlgorithm);
	}

}
