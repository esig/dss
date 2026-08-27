/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.random;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.crypto.prng.FixedSecureRandom;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Default {@code SecureRandomProvider} used in DSS, 
 * returning org.bouncycastle.crypto.prng.FixedSecureRandom instance
 *
 */
public class DSSSecureRandomProvider implements SecureRandomProvider {
	
	/**
	 * DigestAlgorithm used for random string generation
	 */
	private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA512;
	
	/**
	 * The default constructor taking an object to compute seeds from.
	 * When using this constructor, the used binary length is 512 bits.
	 */
	public DSSSecureRandomProvider() {
		// empty
	}

	/**
	 * The default constructor taking an object to compute seeds from.
	 * When using this constructor, the used binary length depends on the digest algorithm.
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for pseudo-random string generation
	 */
	public DSSSecureRandomProvider(DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public SecureRandom getSecureRandom(byte[] seed) {
		return new DSSFixedSecureRandom(seed);
	}

	/**
	 * Local implementation of a SecureRandom, based on the {@code org.bouncycastle.crypto.prng.FixedSecureRandom}
	 * able to derive the new fixed random when exceeding the initial length.
	 *
	 */
	private final class DSSFixedSecureRandom extends SecureRandom {

		private static final long serialVersionUID = -4555932297026053812L;

		/**
		 * Current seed/state.
		 */
		private byte[] seed;

		/**
		 * Current read position within block.
		 */
		private int index;

		/**
		 * Current delegate.
		 */
		private FixedSecureRandom current;

		/**
		 * Default constructor
		 *
		 * @param seed byte array containing a seed value
		 */
		private DSSFixedSecureRandom(byte[] seed) {
			Objects.requireNonNull(seed, "Seed cannot be null");
			this.seed = initialize(seed);
		}

		private byte[] initialize(byte[] seed) {
			return DSSUtils.digest(digestAlgorithm, seed);
		}

		/**
		 * Generates next deterministic block.
		 */
		private void nextBlock() {
			if (current != null) {
				this.seed = initialize(seed);
			}
			this.current = new FixedSecureRandom(seed);
			this.index = 0;
		}

		@Override
		public void nextBytes(byte[] bytes) {
			Objects.requireNonNull(bytes, "Target byte array cannot be null");

			int offset = 0;

			while (offset < bytes.length) {

				if (current == null || current.isExhausted()) {
					nextBlock();
				}

				int available = seed.length - index;
				int requested = bytes.length - offset;

				int length = Math.min(available, requested);

				byte[] chunk = new byte[length];
				current.nextBytes(chunk);

				System.arraycopy(chunk, 0, bytes, offset, length);

				offset += length;
				index += length;
			}
		}

		@Override
		public byte[] generateSeed(int numBytes) {
			byte[] generatedSeed = new byte[numBytes];
			nextBytes(generatedSeed);
			return generatedSeed;
		}

	}

}
