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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignASiCEWithXAdESWithTempFileTest extends CookbookTools {

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
            // import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
            // import eu.europa.esig.dss.asic.common.ZipUtils;
            // import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;

            // Set a TempFileResourcesHandlerBuilder, forcing the signature creation process to work with
            // temporary files. It means that the produced DSSDocument after the signDocument() method will
            // be represented by a FileDocument object, pointing to a real file within the file system.
            TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();

            // #setTempFileDirectory (OPTIONAL) method allows definition of a target folder containing
            // temporary files created during the execution
            tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

            // #setFileNamePrefix (OPTIONAL) sets a prefix for created temporary files
            tempFileResourcesHandlerBuilder.setFileNamePrefix("dss-");

            // #setFileNamePrefix (OPTIONAL) sets a suffix for created temporary files
            tempFileResourcesHandlerBuilder.setFileNameSuffix(".tmp");

            // Create a SecureContainerHandlerBuilder and provide
            // TempFileResourcesHandlerBuilder configuration
            SecureContainerHandlerBuilder secureContainerHandlerBuilder = new SecureContainerHandlerBuilder()
                    .setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);

            // Set SecureContainerHandlerBuilder within ZipUtils instance
            ZipUtils.getInstance().setZipContainerHandlerBuilder(secureContainerHandlerBuilder);

            // Create ASiC service for signature
            ASiCWithXAdESService service = new ASiCWithXAdESService(commonCertificateVerifier);

            // Create the container signature
            ToBeSigned dataToSign = service.getDataToSign(documentsToBeSigned, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedContainer = service.signDocument(documentsToBeSigned, parameters, signatureValue);
            // end::demo[]

            assertInstanceOf(FileDocument.class, signedContainer);

            testFinalDocument(signedContainer);

            File file = ((FileDocument) signedContainer).getFile();
            assertTrue(file.exists());
            assertTrue(file.delete());
            assertFalse(file.exists());
        }
    }

}
