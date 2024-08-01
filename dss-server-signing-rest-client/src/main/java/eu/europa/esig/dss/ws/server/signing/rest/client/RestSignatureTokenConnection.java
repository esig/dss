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
package eu.europa.esig.dss.ws.server.signing.rest.client;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.io.Serializable;
import java.util.List;

/**
 * The server signing service for REST webService
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestSignatureTokenConnection extends Serializable {

	/**
	 * Retrieves all the available keys (private keys entries) from the token.
	 *
	 * @return List of encapsulated private keys
	 */
	@GET
	@Path("keys")
	List<RemoteKeyEntry> getKeys();

	/**
	 * Retrieves a key by its alias
	 * 
	 * @param alias
	 *            the key alias to retrieve
	 * 
	 * @return the RemoteKeyEntry with the given alias
	 * 
	 */
	@GET
	@Path("key/{alias}")
	RemoteKeyEntry getKey(@PathParam("alias") String alias);

	/**
	 * This method signs the {@code toBeSigned} data with the digest
	 * {@code digestAlgorithm} and the given {@code alias}.
	 * 
	 * @param toBeSigned
	 *                        The data that need to be signed
	 * @param digestAlgorithm
	 *                        The digest algorithm to be used before signing
	 * @param alias
	 *                        The key alias to be used
	 * @return The array of bytes representing the signature value
	 */
	@POST
	@Path("sign/{alias}/{algo}")
	SignatureValueDTO sign(ToBeSignedDTO toBeSigned, @PathParam("algo") DigestAlgorithm digestAlgorithm, @PathParam("alias") String alias);

	/**
	 * This method signs the {@code toBeSigned} data with the digest
	 * {@code digestAlgorithm} and the given {@code alias}.
	 *
	 * @param toBeSigned
	 *                        The data that need to be signed
	 * @param signatureAlgorithm
	 *                        The signature algorithm to be used for signing
	 * @param alias
	 *                        The key alias to be used
	 * @return The array of bytes representing the signature value
	 */
	@POST
	@Path("sign-with-signature-algo/{alias}/{signature-algo}")
	SignatureValueDTO sign(ToBeSignedDTO toBeSigned, @PathParam("signature-algo") SignatureAlgorithm signatureAlgorithm,
						   @PathParam("alias") String alias);

	/**
	 * 
	 * This method signs the {@code digest} data with the given {@code alias}.
	 * 
	 * @param digest
	 *               The digested data that need to be signed
	 * @param alias
	 *               The key alias to be used
	 * @return the signature value representation with the used algorithm and the
	 *         binary value
	 */
	@POST
	@Path("sign-digest/{alias}")
	SignatureValueDTO signDigest(DigestDTO digest, @PathParam("alias") String alias);

	/**
	 * This method signs the {@code digest} data with a mask {@code mgf} and the
	 * given {@code alias}.
	 *
	 * @param digest
	 *               The digested data that need to be signed
	 * @param signatureAlgorithm
	 *                        The signature algorithm to be used for signing
	 * @param alias
	 *               The key alias to be used
	 * @return the signature value representation with the used algorithm and the
	 *         binary value
	 */
	@POST
	@Path("sign-digest-with-signature-algo/{alias}/{signature-algo}")
	SignatureValueDTO signDigest(DigestDTO digest, @PathParam("signature-algo") SignatureAlgorithm signatureAlgorithm,
								 @PathParam("alias") String alias);

}
