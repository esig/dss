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
package eu.europa.esig.dss.ws.converter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.LinkedList;
import java.util.List;

/**
 * Contains utils to convert {@code CertificateToken} to {@code RemoteCertificate} and vice versa
 */
public class RemoteCertificateConverter {

	private RemoteCertificateConverter() {
	}
	
	/**
	 * Converts the given {@code remoteCertificate} to a {@code CertificateToken}
	 *
	 * @param remoteCertificate {@link RemoteDocument} to convert
	 * @return {@link CertificateToken}
	 */
	public static CertificateToken toCertificateToken(RemoteCertificate remoteCertificate) {
		if (remoteCertificate == null || Utils.isArrayEmpty(remoteCertificate.getEncodedCertificate())) {
			return null;
		}
		return DSSUtils.loadCertificate(remoteCertificate.getEncodedCertificate());
	}

	/**
	 * Converts the given {@code certificate} to a {@code RemoteCertificate}
	 *
	 * @param certificate {@link CertificateToken} to convert
	 * @return {@link RemoteCertificate}
	 */
	public static RemoteCertificate toRemoteCertificate(CertificateToken certificate) {
		if (certificate == null) {
			return null;
		}
		return new RemoteCertificate(certificate.getEncoded());
	}
	
	/**
	 * Converts the given list of {@code remoteCertificates} to a list of {@code CertificateToken}s
	 *
	 * @param remoteCertificates list of {@link RemoteCertificate}s
	 * @return list of {@link CertificateToken}s
	 */
	public static List<CertificateToken> toCertificateTokens(List<RemoteCertificate> remoteCertificates) {
		if (Utils.isCollectionNotEmpty(remoteCertificates)) {
			List<CertificateToken> certificateTokens = new LinkedList<>();
			for (RemoteCertificate remoteCertificate : remoteCertificates) {
				CertificateToken certificateToken = toCertificateToken(remoteCertificate);
				if (certificateToken != null) {
					certificateTokens.add(certificateToken);
				}
			}
			return certificateTokens;
		}
		return null;
	}

}
