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
package eu.europa.esig.dss.cookbook.example.sign;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.sc.PcscEid;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cookbook.sources.AppletView;
import eu.europa.esig.dss.cookbook.sources.EidPrivateKeyEntry;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

public class EidNativeSignatureTokenConnection extends AbstractSignatureTokenConnection {

	private static final Logger logger = LoggerFactory.getLogger(EidNativeSignatureTokenConnection.class);

	private PcscEid eid;

	/**
	 * The default constructor for EidNativeSignatureTokenConnection.
	 */
	public EidNativeSignatureTokenConnection(AppletView view) {
		this.eid = new PcscEid(view, new Messages(Locale.ENGLISH));
	}

	@Override
	public void close() {
		eid.close();
	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() {
		try {
			eid.isEidPresent();

			List<X509Certificate> signatureChain = eid.getSignCertificateChain();
			List<DSSPrivateKeyEntry> entries = new ArrayList<DSSPrivateKeyEntry>();
			entries.add(new EidPrivateKeyEntry(new CertificateToken(signatureChain.get(0)), signatureChain));
			return entries;
		} catch (Exception e) {
			logger.error("An error occured while retrieving keys : " + e.getMessage(), e);
			throw new DSSException(e);
		}
	}

	// @Override
	public byte[] encryptDigest(byte[] digestValue, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry) throws NoSuchAlgorithmException {
		try {
			eid.isEidPresent();
			return eid.sign(digestValue, digestAlgo.getName());
		} catch (Exception e) {
			logger.error("An error occured while encrypting digest : " + e.getMessage(), e);
			throw new DSSException(e);
		}
	}

}
