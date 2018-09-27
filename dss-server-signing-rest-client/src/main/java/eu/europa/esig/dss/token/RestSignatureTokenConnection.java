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
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestSignatureTokenConnection extends RemoteSignatureTokenConnection {

	@Override
	@GET
	@Path("keys")
	List<RemoteKeyEntry> getKeys() throws DSSException;

	@Override
	@GET
	@Path("key/{alias}")
	RemoteKeyEntry getKey(@PathParam("alias") String alias) throws DSSException;

	@Override
	@POST
	@Path("sign/{alias}/{algo}")
	SignatureValue sign(ToBeSigned toBeSigned, @PathParam("algo") DigestAlgorithm digestAlgorithm, @PathParam("alias") String alias) throws DSSException;

	@Override
	@POST
	@Path("sign/{alias}/{digest-algo}/{mask}")
	SignatureValue sign(ToBeSigned toBeSigned, @PathParam("digest-algo") DigestAlgorithm digestAlgorithm, @PathParam("mask") MaskGenerationFunction mgf,
			@PathParam("alias") String alias) throws DSSException;

}
