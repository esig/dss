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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.RemoteCertificate;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.x509.CertificateToken;

public class RemoteSignatureTokenConnectionImpl implements RemoteSignatureTokenConnection {

	private AbstractKeyStoreTokenConnection token;

	public void setToken(AbstractKeyStoreTokenConnection token) {
		this.token = token;
	}

	@Override
	public List<RemoteKeyEntry> getKeys() throws DSSException {
		List<RemoteKeyEntry> result = new ArrayList<RemoteKeyEntry>();
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
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException {
		return sign(toBeSigned, digestAlgorithm, null, alias);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, String alias) throws DSSException {
		DSSPrivateKeyEntry key = token.getKey(alias);
		return token.sign(toBeSigned, digestAlgorithm, mgf, key);
	}

	private RemoteKeyEntry convert(KSPrivateKeyEntry key) {
		if (key == null) {
			return null;
		}

		RemoteKeyEntry dto = new RemoteKeyEntry();
		dto.setAlias(key.getAlias());
		dto.setEncryptionAlgo(key.getEncryptionAlgorithm());
		dto.setCertificate(getRemoteCertificate(key.getCertificate()));

		CertificateToken[] certificateChain = key.getCertificateChain();
		if (certificateChain != null) {
			RemoteCertificate[] dtos = new RemoteCertificate[certificateChain.length];
			int i = 0;
			for (CertificateToken certificateToken : certificateChain) {
				dtos[i] = getRemoteCertificate(certificateToken);
				i++;
			}
			dto.setCertificateChain(dtos);
		}

		return dto;
	}

	private RemoteCertificate getRemoteCertificate(CertificateToken certificate) {
		RemoteCertificate dto = new RemoteCertificate();
		dto.setEncodedCertificate(certificate.getEncoded());
		return dto;
	}

}
