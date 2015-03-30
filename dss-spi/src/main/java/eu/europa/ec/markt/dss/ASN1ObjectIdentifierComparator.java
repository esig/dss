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
package eu.europa.ec.markt.dss;

import java.util.Comparator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * This class is a Comparator implementation for ASN1ObjectIdentifiers
 *
 */
public class ASN1ObjectIdentifierComparator implements Comparator<ASN1ObjectIdentifier> {

	private static final String REGEX_DOT = "\\.";

	@Override
	public int compare(ASN1ObjectIdentifier o1, ASN1ObjectIdentifier o2) {
		String id1 = o1.getId();
		String id2 = o2.getId();

		String[] split1 = id1.split(REGEX_DOT);
		String[] split2 = id2.split(REGEX_DOT);

		int maxLenght = Math.max(split1.length, split2.length);

		for (int i = 0; i < maxLenght; i++) {
			if (split1.length == i) {
				return -1;
			}
			if (split2.length == i) {
				return 1;
			}

			Integer part1 = Integer.parseInt(split1[i]);
			Integer part2 = Integer.parseInt(split2[i]);

			int compare = part1.compareTo(part2);

			if (compare != 0) {
				return compare;
			}
		}
		return 0;
	}

}
