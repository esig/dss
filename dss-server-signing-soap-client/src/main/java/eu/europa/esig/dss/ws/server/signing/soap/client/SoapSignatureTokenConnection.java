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
package eu.europa.esig.dss.ws.server.signing.soap.client;

import java.io.Serializable;
import java.util.List;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;

/**
 * The server signing service for SOAP webService
 */
@WebService(targetNamespace = "http://server-signing.dss.esig.europa.eu/")
public interface SoapSignatureTokenConnection extends Serializable {

	/**
	 * Retrieves all the available keys (private keys entries) from the token.
	 *
	 * @return List of encapsulated private keys
	 */
	@WebMethod(operationName = "getKeys")
	@WebResult(name = "response")
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
	@WebMethod(operationName = "getKey")
	@WebResult(name = "response")
	RemoteKeyEntry getKey(@WebParam(name = "alias") String alias);

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
	@WebMethod(operationName = "sign")
	@WebResult(name = "response")
	SignatureValueDTO sign(@WebParam(name = "toBeSigned") ToBeSignedDTO toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "alias") String alias);

	/**
	 * This method signs the {@code toBeSigned} data with the digest
	 * {@code digestAlgorithm}, the mask {@code mgf} and the given {@code alias}.
	 * 
	 * @param toBeSigned
	 *                        The data that need to be signed
	 * @param digestAlgorithm
	 *                        The digest algorithm to be used before signing
	 * @param mgf
	 *                        the mask generation function
	 * @param alias
	 *                        The key alias to be used
	 * @return The array of bytes representing the signature value
	 */
	@WebMethod(operationName = "signWithMask")
	@WebResult(name = "response")
	SignatureValueDTO sign(@WebParam(name = "toBeSigned") ToBeSignedDTO toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "maskGenerationFunction") MaskGenerationFunction mgf, @WebParam(name = "alias") String alias);

	/**
	 * This method signs the {@code toBeSigned} data with the
	 * {@code signatureAlgorithm} and the given {@code alias}.
	 *
	 * @param toBeSigned
	 *                        The data that need to be signed
	 * @param signatureAlgorithm
	 *                        The digest algorithm to be used for signing
	 * @param alias
	 *                        The key alias to be used
	 * @return The array of bytes representing the signature value
	 */
	@WebMethod(operationName = "signWithSignatureAlgo")
	@WebResult(name = "response")
	SignatureValueDTO sign(@WebParam(name = "toBeSigned") ToBeSignedDTO toBeSigned,
						   @WebParam(name = "signatureAlgorithm") SignatureAlgorithm signatureAlgorithm,
						   @WebParam(name = "alias") String alias);

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
	@WebMethod(operationName = "signDigest")
	@WebResult(name = "response")
	SignatureValueDTO signDigest(@WebParam(name = "digest") DigestDTO digest, @WebParam(name = "alias") String alias);

	/**
	 * 
	 * This method signs the {@code digest} data with a mask {@code mgf} and the
	 * given {@code alias}.
	 * 
	 * @param digest
	 *               The digested data that need to be signed
	 * @param mgf
	 *               the mask generation function
	 * @param alias
	 *               The key alias to be used
	 * @return the signature value representation with the used algorithm and the
	 *         binary value
	 */
	@WebMethod(operationName = "signDigestWithMask")
	@WebResult(name = "response")
	SignatureValueDTO signDigest(@WebParam(name = "digest") DigestDTO digest, @WebParam(name = "maskGenerationFunction") MaskGenerationFunction mgf,
			@WebParam(name = "alias") String alias);

	/**
	 *
	 * This method signs the {@code digest} data with a {@code signatureAlgorithm} and
	 * the given {@code alias}.
	 *
	 * @param digest
	 *               The digested data that need to be signed
	 * @param signatureAlgorithm
	 *                        The digest algorithm to be used for signing
	 * @param alias
	 *               The key alias to be used
	 * @return the signature value representation with the used algorithm and the
	 *         binary value
	 */
	@WebMethod(operationName = "signDigestWithSignatureAlgo")
	@WebResult(name = "response")
	SignatureValueDTO signDigest(@WebParam(name = "digest") DigestDTO digest,
								 @WebParam(name = "signatureAlgorithm") SignatureAlgorithm signatureAlgorithm,
								 @WebParam(name = "alias") String alias);

}
