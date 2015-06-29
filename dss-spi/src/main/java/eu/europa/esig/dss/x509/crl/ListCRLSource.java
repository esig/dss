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
package eu.europa.esig.dss.x509.crl;

import java.security.cert.X509CRL;
import java.util.ArrayList;

/**
 * This class allows to handle a list CRL source.
 *
 *
 *
 *
 *
 */
public class ListCRLSource extends OfflineCRLSource {

	/**
	 * This is the constructor for this class, it allows to instantiate the list which will contain all {@code X509CRL}.
	 */
	public ListCRLSource() {
		x509CRLList = new ArrayList<X509CRL>();
	}

	/**
	 * This constructor allows to initialize the list of {@code X509CRL} from an {@code OfflineCRLSource}.
	 *
	 * @param crlSource
	 */
	public ListCRLSource(final OfflineCRLSource crlSource) {

		x509CRLList = new ArrayList<X509CRL>(crlSource.getContainedX509CRLs());
	}

	/**
	 * This method allows to add all {@code X509CRL} from one {@code OfflineCRLSource} to this one. If the {@code X509CRL} exists already within the current source then it is
	 * ignored.
	 *
	 * @param offlineCRLSource the source to be added
	 */
	public void addAll(final OfflineCRLSource offlineCRLSource) {

		for (X509CRL x509CRL : offlineCRLSource.x509CRLList) {

			if (!x509CRLList.contains(x509CRL)) {
				x509CRLList.add(x509CRL);
			}
		}
	}
}
