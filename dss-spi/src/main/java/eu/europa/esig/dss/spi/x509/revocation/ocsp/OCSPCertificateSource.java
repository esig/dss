package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.util.Objects;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;

/**
 * Represents a Source of certificates embedded into an OCSP Token
 *
 */
@SuppressWarnings("serial")
public class OCSPCertificateSource extends RevocationCertificateSource {
	
	private final BasicOCSPResp basicOCSPResp;
	
	public OCSPCertificateSource(final BasicOCSPResp basicOCSPResp) {
		Objects.requireNonNull(basicOCSPResp, "BasicOCSPResp must be provided!");
		this.basicOCSPResp = basicOCSPResp;
		
		extractCertificateTokens();
		extractCertificatRefs();
	}
	
	private void extractCertificateTokens() {
		for (final X509CertificateHolder x509CertificateHolder : basicOCSPResp.getCerts()) {
			CertificateToken certificateToken = DSSASN1Utils.getCertificate(x509CertificateHolder);
			addCertificate(certificateToken, CertificateOrigin.BASIC_OCSP_RESP);
		}
	}

	private void extractCertificatRefs() {
		final ResponderId responderId = DSSRevocationUtils.getDSSResponderId(basicOCSPResp.getResponderId());
		CertificateRef signingCertificateRef = new CertificateRef();
		signingCertificateRef.setResponderId(responderId);
		signingCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		addCertificateRef(signingCertificateRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
	}
	
	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.OCSP_RESPONSE;
	}

}
