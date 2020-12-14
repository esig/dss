package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.model.DSSDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class JAdESExtensionCompactBToSerializationLTATest extends AbstractJAdESTestExtension {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        return signatureParameters;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_B;
    }

    @Override
    protected JAdESSignatureParameters getExtensionParameters() {
        JAdESSignatureParameters signatureParameters = super.getExtensionParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        return signatureParameters;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LTA;
    }

    @Override
    protected void onDocumentSigned(DSSDocument signedDocument) {
        super.onDocumentSigned(signedDocument);

        JWSJsonSerializationParser parser = new JWSJsonSerializationParser(signedDocument);
        JWSJsonSerializationObject jsonSerializationObject = parser.parse();
        assertNotNull(jsonSerializationObject);
        assertEquals(JWSSerializationType.JSON_SERIALIZATION,  jsonSerializationObject.getJWSSerializationType());
    }

}
