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
package eu.europa.esig.dss.x509.revocation.crl;

import eu.europa.esig.dss.identifier.CRLBinaryIdentifier;
import eu.europa.esig.dss.x509.RevocationOrigin;

/**
 * This class allows to handle a list CRL source.
 *
 */
@SuppressWarnings("serial")
public class ListCRLSource extends SignatureCRLSource {

	/**
	 * This is the constructor for this class, it allows to instantiate the list which will contain all {@code X509CRL}.
	 */
	public ListCRLSource() {
	}

	/**
	 * This constructor allows to initialize the list of {@code X509CRL} from an {@code OfflineCRLSource}.
	 *
	 * @param crlSource
	 *            an offline crl source
	 */
	public ListCRLSource(OfflineCRLSource crlSource) {
		addAll(crlSource);
	}

	/**
	 * This method allows to add all {@code X509CRL} from one {@code OfflineCRLSource} to this one. If the
	 * {@code X509CRL} exists already within the current source then it is
	 * ignored.
	 *
	 * @param offlineCRLSource
	 *            the source to be added
	 */
	public void addAll(final OfflineCRLSource offlineCRLSource) {
		for (CRLBinaryIdentifier crlBinary : offlineCRLSource.getContainedX509CRLs()) {
			for (RevocationOrigin origin : crlBinary.getOrigins()) {
				addCRLBinary(crlBinary, origin);
			}
		}
		if (offlineCRLSource instanceof SignatureCRLSource) {
			SignatureCRLSource signatureCRLSource = (SignatureCRLSource) offlineCRLSource;
			for (CRLRef crlRef : signatureCRLSource.getAllCRLReferences()) {
				addReference(crlRef, crlRef.getOrigin());
			}
		}
	}

}
