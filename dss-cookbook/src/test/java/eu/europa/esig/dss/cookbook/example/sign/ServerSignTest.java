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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class ServerSignTest extends CookbookTools {

    @Test
    void serverSignTest() throws Exception {

        // GET document to be signed -
        // Return DSSDocument toSignDocument
        DSSDocument toSignDocument = new InMemoryDocument("Hello World!".getBytes());

        // Preparing parameters for a signature creation
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setSigningCertificate(getSigningCert());
        parameters.setCertificateChain(getCertificateChain());
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create signature service for signature creation
        CAdESService service = new CAdESService(commonCertificateVerifier);

        // tag::demo[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.Digest;
        // import eu.europa.esig.dss.model.SignatureValue;
        // import eu.europa.esig.dss.model.ToBeSigned;
        // import eu.europa.esig.dss.spi.DSSUtils;

        // Get the SignedInfo segment that need to be signed providing the original document
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        // Compute the hash of ToBeSigned data to send to the remote server
        byte[] toBeSignedDigest = DSSUtils.digest(parameters.getDigestAlgorithm(), dataToSign.getBytes());
        Digest digest = new Digest(parameters.getDigestAlgorithm(), toBeSignedDigest);

        // Provide the hash of ToBeSigned data to the remote server for signing
        SignatureValue signatureValue = serverSignDigest(digest);
        //SignatureValue signatureValue = serverSign(dataToSign, parameters.getDigestAlgorithm());

        // We invoke the signature service to create a signed document incorporating the obtained Sig
        DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

        // end::demo[]

        testFinalDocument(signedDocument);

    }

    public SignatureValue serverSignDigest(Digest digest) throws IOException {
        return getToken().signDigest(digest, getPrivateKeyEntry());
    }

    public SignatureValue serverSign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm) throws IOException {
        return getToken().sign(toBeSigned, digestAlgorithm, getPrivateKeyEntry());
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
