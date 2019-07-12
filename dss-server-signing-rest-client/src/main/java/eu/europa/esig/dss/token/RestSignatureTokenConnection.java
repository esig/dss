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
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;

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

	@Override
	@POST
	@Path("sign-digest/{alias}")
	SignatureValue signDigest(Digest digest, @PathParam("alias") String alias) throws DSSException;

	@Override
	@POST
	@Path("sign-digest/{alias}/{mask}")
	SignatureValue signDigest(Digest digest, @PathParam("mask") MaskGenerationFunction mgf, @PathParam("alias") String alias) throws DSSException;

}
