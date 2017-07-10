package eu.europa.esig.dss.token;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestSignatureTokenConnection extends RemoteSignatureTokenConnection {

	/**
	 * Retrieves all the available keys (private keys entries) from the QSCD.
	 *
	 * @return List of encapsulated private keys
	 * @throws DSSException
	 *             If there is any problem during the retrieval process
	 */
	@Override
	@GET
	@Path("keys")
	List<RemoteKeyEntry> getKeys() throws DSSException;

	/**
	 * Retrieves a key by its alias
	 * 
	 */
	@Override
	@GET
	@Path("key/{alias}")
	RemoteKeyEntry getKey(@PathParam("alias") String alias) throws DSSException;

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
	@POST
	@Path("sign/{alias}/{algo}")
	SignatureValue sign(ToBeSigned toBeSigned, @PathParam("algo") DigestAlgorithm digestAlgorithm, @PathParam("alias") String alias) throws DSSException;

}
