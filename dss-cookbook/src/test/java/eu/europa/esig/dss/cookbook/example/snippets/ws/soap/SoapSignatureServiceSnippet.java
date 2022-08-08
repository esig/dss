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
package eu.europa.esig.dss.cookbook.example.snippets.ws.soap;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.TimestampOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.ws.signature.soap.SoapDocumentSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.soap.client.SoapDocumentSignatureService;

import java.io.File;

public class SoapSignatureServiceSnippet extends CookbookTools {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // tag::demo[]
            // import eu.europa.esig.dss.ws.signature.soap.SoapDocumentSignatureServiceImpl;
            // import eu.europa.esig.dss.ws.signature.soap.client.SoapDocumentSignatureService;

            // Initializes the SOAP client
            SoapDocumentSignatureService soapClient = new SoapDocumentSignatureServiceImpl();
            // end::demo[]

            // Defines RemoteSignatureParameters
            RemoteSignatureParameters parameters = new RemoteSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setSigningCertificate(new RemoteCertificate(privateKey.getCertificate().getEncoded()));
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // Initialize a RemoteDocument object to be signed
            FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
            RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

            // computes the digest to be signed
            ToBeSignedDTO dataToSign = soapClient.getDataToSign(new DataToSignOneDocumentDTO(toSignDocument, parameters));

            // Creates a SignOneDocumentDTO
            SignatureValue signatureValue = signingToken.sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, privateKey);
            SignOneDocumentDTO signDocument = new SignOneDocumentDTO(toSignDocument, parameters,
                    new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

            // Adds the signature value to the document
            RemoteDocument signedDocument = soapClient.signDocument(signDocument);

            // Define the extension parameters
            RemoteSignatureParameters extendParameters = new RemoteSignatureParameters();
            extendParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

            // Extends the existing signature
            RemoteDocument extendedDocument = soapClient.extendDocument(new ExtendDocumentDTO(signedDocument, extendParameters));

            // Defines timestamp parameters
            RemoteTimestampParameters remoteTimestampParameters = new RemoteTimestampParameters();
            remoteTimestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // Defines a Timestamp document DTO
            TimestampOneDocumentDTO timestampOneDocumentDTO = new TimestampOneDocumentDTO(extendedDocument, remoteTimestampParameters);

            // Timestamps a provided document (available for PDF, ASiC-E and ASiC-S container formats)
            RemoteDocument timestampedDocument = soapClient.timestampDocument(timestampOneDocumentDTO);
        }

    }

}