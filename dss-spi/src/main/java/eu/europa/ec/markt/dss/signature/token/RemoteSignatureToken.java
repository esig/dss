package eu.europa.ec.markt.dss.signature.token;

import java.util.List;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class RemoteSignatureToken implements SignatureTokenConnection {
	@Override
	public void close() {

	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		return null;
	}

	@Override
	public byte[] sign(byte[] bytes, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {

		return sign(bytes, digestAlgorithm);
	}

	/**
	 * @param bytes           The array of bytes to be signed
	 * @param digestAlgorithm The digest algorithm to use to create the hash to sign
	 * @return The array of bytes representing the signature value
	 * @throws DSSException If there is any problem during the signature process
	 */
	public abstract byte[] sign(byte[] bytes, DigestAlgorithm digestAlgorithm) throws DSSException;
}
