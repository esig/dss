package eu.europa.esig.dss.cbades.vical;

import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.signature.AbstractCBAdESTestSignature;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.signature.CBAdESTimestampParameters;
import eu.europa.esig.dss.cbades.validation.COSEDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class CborVICALSignatureParametersBuilderTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private CBAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument(new File("src/test/resources/vical/vical.cbor"));
        service = new CBAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        CborVICALSignatureParametersBuilder signatureParametersBuilder = getSignatureParametersBuilder();
        // signatureParametersBuilder.assertConfigurationIsValid(); // TODO : not implemented yet
        signatureParameters = signatureParametersBuilder.build();
        return super.sign();
    }

    protected CborVICALSignatureParametersBuilder getSignatureParametersBuilder() {
        return new CborVICALSignatureParametersBuilder(getSigningCert(), documentToSign);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        COSEDocumentValidator coseDocumentValidator = assertInstanceOf(COSEDocumentValidator.class, super.getValidator(signedDocument));
        // The external_aad field used in the Sig_ structure shall be a bytestring of size zero.
        coseDocumentValidator.setExternallySuppliedData(new InMemoryDocument("".getBytes()));
        return coseDocumentValidator;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_521_USER;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        try {
            COSEParser coseParser = COSEParser.fromBinaries(byteArray);
            assertNotNull(coseParser);

            COSESignStructure coseSignStructure = coseParser.parse();
            assertNotNull(coseSignStructure);

            COSESign1 coseSign1 = assertInstanceOf(COSESign1.class, coseSignStructure);
            assertFalse(coseSign1.isTagged());

            COSEProtectedHeader protectedHeader = coseSign1.getProtectedHeader();
            assertNotNull(protectedHeader);
            assertEquals(-36L, protectedHeader.getAsLong(1L)); // alg = ES512

            CBORObject payload = coseSign1.getPayload();
            assertNotNull(payload);

            CBORByteString signature = coseSign1.getSignature();
            assertNotNull(signature);

            COSEUnprotectedHeader unprotectedHeader = coseSign1.getUnprotectedHeader();
            assertNotNull(unprotectedHeader);

            assertArrayEquals(getSigningCert().getEncoded(), unprotectedHeader.getAsBinaries(33L)); // x5chain

        } catch (Exception e) {
            fail(e);
        }
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}