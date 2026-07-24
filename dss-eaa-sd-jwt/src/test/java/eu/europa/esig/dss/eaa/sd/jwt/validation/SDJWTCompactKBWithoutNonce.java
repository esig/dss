package eu.europa.esig.dss.eaa.sd.jwt.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

class SDJWTCompactKBWithoutNonce extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-compact-kb-no-nonce.json"));
    }

    @Override
    protected void checkClaims(final DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);
        final AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertNull(eaa.getKeyBindingSignatureNonce());
        assertNotNull(eaa.getKeyBindingSignatureAudience());
        assertNotNull(eaa.getKeyBindingSignatureIssuanceTime());
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
