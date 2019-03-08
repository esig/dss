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

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

@WebService
public interface SoapSignatureTokenConnection extends RemoteSignatureTokenConnection {

	@Override
	@WebMethod(operationName = "getKeys")
	@WebResult(name = "response")
	List<RemoteKeyEntry> getKeys() throws DSSException;

	@Override
	@WebMethod(operationName = "getKey")
	@WebResult(name = "response")
	RemoteKeyEntry getKey(@WebParam(name = "alias") String alias) throws DSSException;

	@Override
	@WebMethod(operationName = "sign")
	@WebResult(name = "response")
	SignatureValue sign(@WebParam(name = "toBeSigned") ToBeSigned toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "alias") String alias) throws DSSException;

	@Override
	@WebMethod(operationName = "signWithMask")
	@WebResult(name = "response")
	SignatureValue sign(@WebParam(name = "toBeSigned") ToBeSigned toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "maskGenerationFunction") MaskGenerationFunction mgf, @WebParam(name = "alias") String alias) throws DSSException;

	@Override
	@WebMethod(operationName = "signDigest")
	@WebResult(name = "response")
	SignatureValue signDigest(@WebParam(name = "digest") Digest digest, @WebParam(name = "alias") String alias) throws DSSException;

	@Override
	@WebMethod(operationName = "signDigestWithMask")
	@WebResult(name = "response")
	SignatureValue signDigest(@WebParam(name = "digest") Digest digest, @WebParam(name = "maskGenerationFunction") MaskGenerationFunction mgf,
			@WebParam(name = "alias") String alias) throws DSSException;

}
