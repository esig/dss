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
package eu.europa.esig.dss.ws.server.signing.common;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;

import java.util.ArrayList;
import java.util.List;

/**
 * Default implementation of a remote signing service
 */
public class RemoteSignatureTokenConnectionImpl implements RemoteSignatureTokenConnection {

	/** The KeyStore token connection */
	private AbstractKeyStoreTokenConnection token;

	/**
	 * Sets the connection to the KeyStore
	 *
	 * @param token {@link AbstractKeyStoreTokenConnection}
	 */
	public void setToken(AbstractKeyStoreTokenConnection token) {
		this.token = token;
	}

	@Override
	public List<RemoteKeyEntry> getKeys() throws DSSException {
		List<RemoteKeyEntry> result = new ArrayList<>();
		List<DSSPrivateKeyEntry> keys = token.getKeys();
		for (DSSPrivateKeyEntry keyEntry : keys) {
			result.add(convert((KSPrivateKeyEntry) keyEntry));
		}
		return result;
	}

	@Override
	public RemoteKeyEntry getKey(String alias) throws DSSException {
		KSPrivateKeyEntry key = (KSPrivateKeyEntry) token.getKey(alias);
		return convert(key);
	}

	@Override
	public SignatureValueDTO sign(ToBeSignedDTO toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException {
		return sign(toBeSigned, digestAlgorithm, null, alias);
	}

	@Override
	public SignatureValueDTO sign(ToBeSignedDTO toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, String alias) throws DSSException {
		DSSPrivateKeyEntry key = token.getKey(alias);
		return DTOConverter.toSignatureValueDTO(token.sign(DTOConverter.toToBeSigned(toBeSigned), digestAlgorithm, mgf, key));
	}

	@Override
	public SignatureValueDTO signDigest(DigestDTO digest, String alias) throws DSSException {
		return signDigest(digest, null, alias);
	}

	@Override
	public SignatureValueDTO signDigest(DigestDTO digest, MaskGenerationFunction mgf, String alias) throws DSSException {
		DSSPrivateKeyEntry key = token.getKey(alias);
		return DTOConverter.toSignatureValueDTO(token.signDigest(DTOConverter.toDigest(digest), mgf, key));
	}

	private RemoteKeyEntry convert(KSPrivateKeyEntry key) {
		if (key == null) {
			return null;
		}

		RemoteKeyEntry dto = new RemoteKeyEntry();
		dto.setAlias(key.getAlias());
		dto.setEncryptionAlgo(key.getEncryptionAlgorithm());
		dto.setCertificate(RemoteCertificateConverter.toRemoteCertificate(key.getCertificate()));

		CertificateToken[] certificateChain = key.getCertificateChain();
		if (certificateChain != null) {
			RemoteCertificate[] dtos = new RemoteCertificate[certificateChain.length];
			int i = 0;
			for (CertificateToken certificateToken : certificateChain) {
				dtos[i] = RemoteCertificateConverter.toRemoteCertificate(certificateToken);
				i++;
			}
			dto.setCertificateChain(dtos);
		}

		return dto;
	}

}
