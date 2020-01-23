package eu.europa.esig.dss.cookbook.example.snippets;

import java.nio.charset.Charset;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;
import eu.europa.esig.dss.ws.server.signing.rest.RestSignatureTokenConnectionImpl;
import eu.europa.esig.dss.ws.server.signing.rest.client.RestSignatureTokenConnection;

public class RestServerSigningSnippet {
	
	@SuppressWarnings("unused")
	public void demo() {
		// tag::demo[]
		
		// Instantiate a RestSignatureTokenConnection
		RestSignatureTokenConnection remoteToken = new RestSignatureTokenConnectionImpl();
		
		// Retrieves available keys on server side
		List<RemoteKeyEntry> keys = remoteToken.getKeys();

		String alias = keys.get(0).getAlias();

		// Create a toBeSigned DTO
		ToBeSignedDTO toBeSigned = new ToBeSignedDTO(DSSUtils.digest(DigestAlgorithm.SHA256, "Hello world!".getBytes(Charset.defaultCharset())));
		
		// Signs the digest value with the given key
		SignatureValueDTO signatureValue = remoteToken.sign(toBeSigned, DigestAlgorithm.SHA256, alias);

		// Retrieves a key on the server side by its alias
		RemoteKeyEntry key = remoteToken.getKey(alias);
		
		// end::demo[]
	}

}
