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

import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.junit.jupiter.api.Test;

/**
 * How to sign with CB-AdES-BASELINE-B enveloping signature.
 */
class SignXmlCbadesBTest extends CookbookTools {

    @Test
    void signCBAdESBaselineB() {

        // GET document to be signed -
        // Return DSSDocument toSignDocument
        prepareXmlDoc();

        DSSDocument externallySuppliedData = new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY);

        // Get a token connection based on a pkcs12 file commonly used to store private
        // keys with accompanying public key certificates, protected with a password-based
        // symmetric key -
        // Return AbstractSignatureTokenConnection signingToken

        // and it's first private key entry from the PKCS12 store
        // Return DSSPrivateKeyEntry privateKey *****
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // tag::demo[]
            // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
            // import eu.europa.esig.dss.enumerations.JWSSerializationType;
            // import eu.europa.esig.dss.enumerations.SignatureLevel;
            // import eu.europa.esig.dss.enumerations.SignaturePackaging;
            // import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
            // import eu.europa.esig.dss.cbades.signature.CBAdESService;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

            // Prepare parameters for the CB-AdES signature
            CBAdESSignatureParameters parameters = new CBAdESSignatureParameters();
            // Choose the level of the signature (-B, -T, -LT, -LTA).
            parameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
            // Choose the type of the signature packaging (ENVELOPING, DETACHED).
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            // tag::structure[]
            // Choose the structure of the signature (COSE_SIGN1, COSE_SIGN)
            parameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
            // Choose whether the signature's CBOR element is to be tagged
            parameters.setTagged(true);
            // end::structure[]

            // tag::externally-supplied-data[]
            // (Optional) Provide externally supplied data
            parameters.setExternallySuppliedData(externallySuppliedData);
            // end::externally-supplied-data[]

            // Set the digest algorithm
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            // Set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // Set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            // Create CBAdESService for signature
            CBAdESService service = new CBAdESService(commonCertificateVerifier);

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

            // We invoke the CBAdESService to sign the document with the signature value obtained in
            // the previous step.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // end::demo[]

            testFinalDocument(signedDocument);
        }
    }

}
