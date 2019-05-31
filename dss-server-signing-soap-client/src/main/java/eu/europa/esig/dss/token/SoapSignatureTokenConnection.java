package eu.europa.esig.dss.token;

import java.util.List;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

@WebService
public interface SoapSignatureTokenConnection extends RemoteSignatureTokenConnection {

	/**
	 * Retrieves all the available keys (private keys entries) from the QSCD.
	 *
	 * @return List of encapsulated private keys
	 * @throws DSSException
	 *             If there is any problem during the retrieval process
	 */
	@Override
	@WebResult(name = "response")
	List<RemoteKeyEntry> getKeys() throws DSSException;

	/**
	 * Retrieves a key by its alias
	 * 
	 */
	@Override
	@WebResult(name = "response")
	RemoteKeyEntry getKey(@WebParam(name = "alias") String alias) throws DSSException;

	/**
	 * @param toBeSigned
	 *            The data that need to be signed
	 * @param digestAlgorithm
	 *            The digest algorithm to be used before signing
	 * @param alias
	 *            The key alias to be used
	 * @return The array of bytes representing the signature value
	 * @throws DSSException
	 *             If there is any problem during the signature process
	 */
	@Override
	@WebResult(name = "response")
	SignatureValue sign(@WebParam(name = "toBeSigned") ToBeSigned toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "alias") String alias) throws DSSException;

}
