/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignASiCWithSimpleFilenameFactoryTest extends CookbookTools {

    @Test
    void signAndMergeContainersTest() throws Exception {

        // Prepare documents to be signed
        List<DSSDocument> documentsToBeSigned = Arrays.asList(
                new FileDocument("src/main/resources/xml_example.xml"),
                new FileDocument("src/main/resources/hello-world.pdf"));

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // Preparing parameters for the ASiC-E with XAdES signature
            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

            // tag::demo[]
            // import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
            // import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;

            // Create ASiC service for signature
            ASiCWithXAdESService service = new ASiCWithXAdESService(commonCertificateVerifier);

            // Create a filename factory and provide a custom filename conformant to rules defined in EN 319 162-1
            SimpleASiCWithXAdESFilenameFactory simpleASiCWithXAdESFilenameFactory = new SimpleASiCWithXAdESFilenameFactory();
            simpleASiCWithXAdESFilenameFactory.setSignatureFilename("signatures-NOWINA.xml");

            // Provide the factory to the ASiCWithXAdESService
            service.setAsicFilenameFactory(simpleASiCWithXAdESFilenameFactory);

            // Create the container signature
            ToBeSigned dataToSign = service.getDataToSign(documentsToBeSigned, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedContainer = service.signDocument(documentsToBeSigned, parameters, signatureValue);
            // end::demo[]

            ASiCWithXAdESContainerExtractor containerExtractor = new ASiCWithXAdESContainerExtractor(signedContainer);
            ASiCContent asicContent = containerExtractor.extract();

            List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
            assertEquals(1, signatureDocuments.size());
            assertEquals("META-INF/signatures-NOWINA.xml", signatureDocuments.get(0).getName());

            testFinalDocument(signedContainer);
        }
    }

}
