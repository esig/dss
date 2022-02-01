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
