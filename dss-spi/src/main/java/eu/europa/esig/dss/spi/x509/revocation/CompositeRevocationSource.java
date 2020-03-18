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
package eu.europa.esig.dss.spi.x509.revocation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;

public class CompositeRevocationSource<R extends Revocation> implements RevocationSource<R>, MultipleRevocationSource<R> {

	private static final long serialVersionUID = 8870377682436878544L;

	private static final Logger LOG = LoggerFactory.getLogger(CompositeRevocationSource.class);

	private final List<RevocationSource<R>> revocationSources;

	public CompositeRevocationSource(List<RevocationSource<R>> revocationSources) {
		Objects.requireNonNull(revocationSources, "RevocationSources is null");
		this.revocationSources = revocationSources;
	}

	@Override
	public RevocationToken<R> getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		for (RevocationSource<R> revocationSource : revocationSources) {
			try {
				RevocationToken<R> revocationToken = revocationSource.getRevocationToken(certificateToken, issuerCertificateToken);
				if (revocationToken != null) {
					return revocationToken;
				}
			} catch (Exception e) {
				LOG.warn("Exception occurred when accessing revocation from the source of class [{}] for a certificate with Id: [{}]",
						revocationSource.getClass(), certificateToken.getDSSIdAsString());
			}
		}
		return null;
	}

	@Override
	public List<RevocationToken<R>> getRevocationTokens(final CertificateToken certificateToken,
			final CertificateToken issuerCertificateToken) {
		List<RevocationToken<R>> result = new ArrayList<>();
		for (RevocationSource<R> revocationSource : revocationSources) {
			try {
				RevocationToken<R> revocationToken = revocationSource.getRevocationToken(certificateToken, issuerCertificateToken);
				if (revocationToken != null) {
					result.add(revocationToken);
				}
			} catch (Exception e) {
				LOG.warn(
						"Exception occurred when accessing revocation from the source of class [{}] for a certificate with Id: [{}]",
						revocationSource.getClass(), certificateToken.getDSSIdAsString());
			}
		}
		return result;
	}

}
