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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;

import java.io.InputStream;
import java.util.List;

/**
 * This class allows to provide a CRL source based on the list of external CRL(s).
 *
 */
public class ExternalResourcesCRLSource extends OfflineCRLSource {

	private static final long serialVersionUID = -985602836642741439L;

	/**
	 * This constructor allows building of a CRL source from an array of resource paths.
	 *
	 * @param paths
	 *            paths to be loaded as CRL
	 */
	public ExternalResourcesCRLSource(final String... paths) {
		for (final String pathItem : paths) {
			addCRLToken(getClass().getResourceAsStream(pathItem));
		}
	}

	/**
	 * This constructor allows building of a CRL source from an array of <code>InputStream</code>s.
	 *
	 * @param inputStreams
	 *            an array of <code>InputStream</code>s to be loaded as CRL
	 */
	public ExternalResourcesCRLSource(final InputStream... inputStreams) {
		for (final InputStream inputStream : inputStreams) {
			addCRLToken(inputStream);
		}
	}

	/**
	 * This constructor allows building of a CRL source from an array of <code>DSSDocument</code>s.
	 *
	 * @param dssDocuments
	 *            an array of <code>DSSDocument</code>s to be loaded as CRL
	 */
	public ExternalResourcesCRLSource(final DSSDocument... dssDocuments) {
		for (final DSSDocument document : dssDocuments) {
			addCRLToken(document.openStream());
		}
	}

	private void addCRLToken(final InputStream inputStream) {
		try (InputStream is = inputStream) {
			addBinary(CRLUtils.buildCRLBinary(Utils.toByteArray(is)), RevocationOrigin.EXTERNAL);
		} catch (Exception e) {
			throw new DSSException("Unable to parse the stream (CRL is expected)", e);
		}
	}

	@Override
	public List<RevocationToken<CRL>> getRevocationTokens(CertificateToken certificate, CertificateToken issuer) {
		List<RevocationToken<CRL>> revocationTokens = super.getRevocationTokens(certificate, issuer);
		for (RevocationToken<CRL> revocationToken : revocationTokens) {
			revocationToken.setExternalOrigin(RevocationOrigin.EXTERNAL);
		}
		return revocationTokens;
	}

}
