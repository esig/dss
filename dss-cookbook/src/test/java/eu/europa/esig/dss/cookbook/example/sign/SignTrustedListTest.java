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

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

public class SignTrustedListTest extends CookbookTools {

    @Test
    public void sign() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            // tag::demo[]
            DSSDocument trustedList = new FileDocument("src/main/resources/trusted-list.xml");

            DSSPrivateKeyEntry privateKeyEntry = signingToken.getKeys().get(0);
            CertificateToken signingCertificate = privateKeyEntry.getCertificate();

            // This class creates the appropriated XAdESSignatureParameters object to sign a trusted list.
            // It handles the configuration complexity and creates a ready-to-be-used XAdESSignatureParameters with a correct configuration.
            TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, trustedList);
            XAdESSignatureParameters parameters = builder.build();

            XAdESService service = new XAdESService(new CommonCertificateVerifier());

            ToBeSigned dataToSign = service.getDataToSign(trustedList, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry);
            DSSDocument signedTrustedList = service.signDocument(trustedList, parameters, signatureValue);

            // end::demo[]

            testFinalDocument(signedTrustedList);
        }

    }

}
