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
package eu.europa.esig.dss.cookbook.example.snippets.ws.soap;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;
import eu.europa.esig.dss.ws.server.signing.soap.SoapSignatureTokenConnectionImpl;
import eu.europa.esig.dss.ws.server.signing.soap.client.SoapSignatureTokenConnection;

import java.util.List;

public class SoapServerSigningServiceSnippet {

    @SuppressWarnings("unused")
    public void demo() {
        // tag::demo[]
        // import eu.europa.esig.dss.ws.server.signing.soap.SoapSignatureTokenConnectionImpl;
        // import eu.europa.esig.dss.ws.server.signing.soap.client.SoapSignatureTokenConnection;

        // Instantiate a SoapSignatureTokenConnection
        SoapSignatureTokenConnection remoteToken = new SoapSignatureTokenConnectionImpl();
        // end::demo[]

        // Retrieves available keys on server side
        List<RemoteKeyEntry> keys = remoteToken.getKeys();

        String alias = keys.get(0).getAlias();

        // Retrieves a key on the server side by its alias
        RemoteKeyEntry key = remoteToken.getKey(alias);

        DSSDocument documentToSign = new InMemoryDocument("Hello world!".getBytes());

        // Create a toBeSigned DTO
        ToBeSignedDTO toBeSigned = new ToBeSignedDTO(DSSUtils.toByteArray(documentToSign));

        // Signs the document with a given Digest Algorithm and alias for a key to use
        // Signs the digest value with the given key
        SignatureValueDTO signatureValue = remoteToken.sign(toBeSigned, DigestAlgorithm.SHA256, alias);

        // Or alternatively we can sign the document by providing digest only

        // Prepare digestDTO.
        // NOTE: the used Digest algorithm must be the same!
        DigestDTO digestDTO = new DigestDTO(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, documentToSign));

        // Signs the digest
        SignatureValueDTO signatureValueFromDigest = remoteToken.signDigest(digestDTO, alias);
    }

}
