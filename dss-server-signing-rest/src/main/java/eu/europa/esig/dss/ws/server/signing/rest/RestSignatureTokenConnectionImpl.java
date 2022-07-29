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
package eu.europa.esig.dss.ws.server.signing.rest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.common.RemoteSignatureTokenConnection;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;
import eu.europa.esig.dss.ws.server.signing.rest.client.RestSignatureTokenConnection;

import java.util.List;

/**
 * The REST implementation of server signing
 */
@SuppressWarnings("serial")
public class RestSignatureTokenConnectionImpl implements RestSignatureTokenConnection {

	/** The connection to the remote token */
	private RemoteSignatureTokenConnection token;

	/**
	 * Default construction instantiating object with null token connection
	 */
	public RestSignatureTokenConnectionImpl() {
	}

	/**
	 * Sets remote token connection
	 *
	 * @param token {@link RemoteSignatureTokenConnection}
	 */
	public void setToken(RemoteSignatureTokenConnection token) {
		this.token = token;
	}

	@Override
	public List<RemoteKeyEntry> getKeys() throws DSSException {
		return token.getKeys();
	}

	@Override
	public RemoteKeyEntry getKey(String alias) throws DSSException {
		return token.getKey(alias);
	}

	@Override
	public SignatureValueDTO sign(ToBeSignedDTO toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException {
		return token.sign(toBeSigned, digestAlgorithm, alias);
	}

	@Override
	public SignatureValueDTO sign(ToBeSignedDTO toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, String alias) throws DSSException {
		return token.sign(toBeSigned, digestAlgorithm, mgf, alias);
	}

	@Override
	public SignatureValueDTO signDigest(DigestDTO digest, String alias) throws DSSException {
		return token.signDigest(digest, alias);
	}

	@Override
	public SignatureValueDTO signDigest(DigestDTO digest, MaskGenerationFunction mgf, String alias) throws DSSException {
		return token.signDigest(digest, mgf, alias);
	}

}
