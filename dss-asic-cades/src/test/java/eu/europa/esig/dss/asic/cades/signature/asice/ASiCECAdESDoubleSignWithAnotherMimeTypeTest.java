/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESSignatureDataToSignHelperBuilder;
import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This unit test is used to show a possibility with a custom code to define
 * custom document MimeType after signing (see DSS-2586)
 *
 */
public class ASiCECAdESDoubleSignWithAnotherMimeTypeTest extends AbstractASiCECAdESTestSignature {

    private static DSSDocument originalDocument;

    private MockASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new MockASiCWithCAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        ASiCContent asicContent = new ASiCWithCAdESContainerExtractor(signedDocument).extract();
        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());

        DSSDocument signerDocument = signedDocuments.get(0);
        signerDocument.setMimeType(MimeType.HTML);

        ToBeSigned dataToSign = service.getDataToSign(asicContent, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
                getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
        return service.signDocument(asicContent, signatureParameters, signatureValue);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkManifests(List<DSSDocument> manifestDocuments) {
        super.checkManifests(manifestDocuments);

        assertEquals(2, manifestDocuments.size());

        boolean textMimeTypeFound = false;
        boolean htmlMimeTypeFound = false;
        for (DSSDocument manifest : manifestDocuments) {
            ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(manifest);
            assertNotNull(manifestFile);

            List<ManifestEntry> entries = manifestFile.getEntries();
            assertEquals(1, entries.size());

            ManifestEntry manifestEntry = entries.get(0);

            MimeType mimeType = manifestEntry.getMimeType();
            assertNotNull(mimeType);
            if (MimeType.TEXT.equals(mimeType)) {
                textMimeTypeFound = true;
            } else if (MimeType.HTML.equals(mimeType)) {
                htmlMimeTypeFound = true;

            }
        }
        assertTrue(textMimeTypeFound);
        assertTrue(htmlMimeTypeFound);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    private class MockASiCWithCAdESService extends ASiCWithCAdESService {

        /**
         * The default constructor to instantiate the service
         *
         * @param certificateVerifier {@link CertificateVerifier} to use
         */
        public MockASiCWithCAdESService(CertificateVerifier certificateVerifier) {
            super(certificateVerifier);
        }

        private ToBeSigned getDataToSign(ASiCContent asicContent, ASiCWithCAdESSignatureParameters parameters) {
            GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESSignatureDataToSignHelperBuilder()
                    .build(asicContent, parameters);

            CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
            cadesParameters.getContext().setDetachedContents(dataToSignHelper.getDetachedContents());

            DSSDocument toBeSigned = dataToSignHelper.getToBeSigned();
            return getCAdESService().getDataToSign(toBeSigned, cadesParameters);
        }

        private DSSDocument signDocument(ASiCContent asicContent, ASiCWithCAdESSignatureParameters parameters,
                                        SignatureValue signatureValue) {
            GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESSignatureDataToSignHelperBuilder()
                    .build(asicContent, parameters);

            ASiCParameters asicParameters = parameters.aSiC();

            CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
            cadesParameters.getContext().setDetachedContents(dataToSignHelper.getDetachedContents());

            DSSDocument toBeSigned = dataToSignHelper.getToBeSigned();
            if (ASiCContainerType.ASiC_E == asicParameters.getContainerType()) {
                asicContent.getManifestDocuments().add(toBeSigned); // XML Document in case of ASiC-E container
            }

            final DSSDocument signature = getCAdESService().signDocument(toBeSigned, cadesParameters, signatureValue);
            final String newSignatureFileName = dataToSignHelper.getSignatureFilename();
            signature.setName(newSignatureFileName);

            ASiCUtils.addOrReplaceDocument(asicContent.getSignatureDocuments(), signature);

            final DSSDocument asicContainer = buildASiCContainer(asicContent, parameters.getZipCreationDate());
            asicContainer.setName(getFinalDocumentName(asicContainer, SigningOperation.SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
            parameters.reinit();
            return asicContainer;
        }

    }

}
