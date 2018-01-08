package eu.europa.esig.dss.token;

import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public interface RemoteSignatureTokenConnection {

	/**
	 * Retrieves all the available keys (private keys entries) from the QSCD.
	 *
	 * @return List of encapsulated private keys
	 * @throws DSSException
	 *             If there is any problem during the retrieval process
	 */
	List<RemoteKeyEntry> getKeys() throws DSSException;

	/**
	 * Retrieves a key by its alias
	 * 
	 * @param alias
	 *            the key alias to retrieve
	 * 
	 * @return the RemoteKeyEntry with the given alias
	 * 
	 */
	RemoteKeyEntry getKey(String alias) throws DSSException;

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
	SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException;

}