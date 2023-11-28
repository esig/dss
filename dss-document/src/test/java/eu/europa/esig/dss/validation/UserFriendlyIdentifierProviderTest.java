package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class UserFriendlyIdentifierProviderTest {

    @Test
    public void certificateRefTest() {
        CertificateRef certificateRef = new CertificateRef();
        Exception exception = assertThrows(DSSException.class, () -> new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));
        assertEquals("One of [certDigest, publicKeyDigest, issuerInfo, x509Uri] must be defined for a CertificateRef!", exception.getMessage());

        certificateRef.setResponderId(new ResponderId(null, null));
        exception = assertThrows(DSSException.class, () -> new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));
        assertEquals("One of [certDigest, publicKeyDigest, issuerInfo, x509Uri] must be defined for a CertificateRef!", exception.getMessage());

        certificateRef.setResponderId(new ResponderId(new X500Principal("CN=CommonName"), null));
        assertEquals("CERTIFICATE_CommonName", new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));

        certificateRef.setResponderId(new ResponderId(null, DSSUtils.digest(DigestAlgorithm.SHA1, "ski".getBytes())));
        assertEquals("CERTIFICATE", new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));

        certificateRef.setCertificateIdentifier(new SignerIdentifier());
        assertEquals("CERTIFICATE", new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));

        SignerIdentifier signerIdentifier = new SignerIdentifier();
        signerIdentifier.setIssuerName(new X500Principal("CN=IssuerName"));
        certificateRef.setCertificateIdentifier(signerIdentifier);
        assertEquals("CERTIFICATE_ISSUER-IssuerName", new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));

        signerIdentifier.setSerialNumber(BigInteger.valueOf(123456879));
        certificateRef.setCertificateIdentifier(signerIdentifier);
        assertEquals("CERTIFICATE_ISSUER-IssuerName_SERIAL-123456879", new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));

        signerIdentifier.setIssuerName(null);
        certificateRef.setCertificateIdentifier(signerIdentifier);
        assertEquals("CERTIFICATE_SERIAL-123456879", new UserFriendlyIdentifierProvider().getIdAsString(certificateRef));
    }

}
