package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * Returns the original hash-based calculated {@code java.lang.String} identifier for the given token
 */
public class OriginalIdentifierProvider implements TokenIdentifierProvider {

    @Override
    public String getIdAsString(AdvancedSignature signature) {
        return signature.getId();
    }

    @Override
    public String getIdAsString(Token token) {
        return token.getDSSIdAsString();
    }

    @Override
    public String getIdAsString(SignatureScope signatureScope) {
        return signatureScope.getDSSIdAsString();
    }

    @Override
    public String getIdAsString(TLInfo tlInfo) {
        return tlInfo.getDSSIdAsString();
    }

    @Override
    public String getIdAsString(CertificateRef certificateRef) {
        return certificateRef.getDSSIdAsString();
    }

    @Override
    public String getIdAsString(RevocationRef<?> revocationRef) {
        return revocationRef.getDSSIdAsString();
    }

    @Override
    public String getIdAsString(EncapsulatedRevocationTokenIdentifier<?> revocationIdentifier) {
        return revocationIdentifier.asXmlId();
    }

}
