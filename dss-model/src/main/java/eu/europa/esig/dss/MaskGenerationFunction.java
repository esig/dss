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
package eu.europa.esig.dss;

/**
 * Supported mask generation functions.
 */
public enum MaskGenerationFunction {

	MGF1_SHA1(DigestAlgorithm.SHA1, 20),

	MGF1_SHA224(DigestAlgorithm.SHA224, 28),

	MGF1_SHA256(DigestAlgorithm.SHA256, 32),

	MGF1_SHA384(DigestAlgorithm.SHA384, 48),

	MGF1_SHA512(DigestAlgorithm.SHA512, 64);

	private final DigestAlgorithm digestAlgorithm;
	private final int saltLength;

	private MaskGenerationFunction(DigestAlgorithm digestAlgorithm, int saltLength) {
		this.digestAlgorithm = digestAlgorithm;
		this.saltLength = saltLength;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public int getSaltLength() {
		return saltLength;
	}

	public static MaskGenerationFunction fromDigestAlgo(String id) {
		for (MaskGenerationFunction mgf : values()) {
			if (id.equals(mgf.getDigestAlgorithm().getOid())) {
				return mgf;
			}
		}
		return null;
	}

	public static MaskGenerationFunction forName(String mgfName, MaskGenerationFunction defaultMGF) {
		for (MaskGenerationFunction mgf : values()) {
			if (mgfName.equals(mgf.name())) {
				return mgf;
			}
		}
		return defaultMGF;
	}

}
