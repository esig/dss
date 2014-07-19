/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.token;

/**
 * Constants shared between PKCS#11 and PC/SC. Needed to isolate these since SunPKCS11 is not always available. Windows 64 bit has
 * no sunpkcs11.jar yet (JRE 1.6.0_20).
 * 
 * 
 * @version $Revision$ - $Date$
 */

public interface Constants {

	//@formatter:off
	static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14 };

	static final byte[] SHA224_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x04, 0x1c };

	static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20 };

	static final byte[] SHA384_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30 };

	static final byte[] SHA512_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40 };

	static final byte[] RIPEMD160_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x04, 0x14 };

	static final byte[] RIPEMD128_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x1b, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x02, 0x04, 0x10 };

	static final byte[] RIPEMD256_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x2b, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x03, 0x04, 0x20 };

	static final byte[] MD5_DIGEST_INFO_PREFIX = new byte[] { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
	//@formatter:on

}
